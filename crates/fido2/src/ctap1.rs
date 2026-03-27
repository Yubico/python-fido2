// Copyright (c) 2026 Yubico AB
// All rights reserved.
//
//   Redistribution and use in source and binary forms, with or
//   without modification, are permitted provided that the following
//   conditions are met:
//
//    1. Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//    2. Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! CTAP1/U2F protocol implementation.

use crate::ctap::{ApduError, CtapDevice, apdu, cmd};

/// CTAP1 instruction codes.
pub mod ins {
    pub const REGISTER: u8 = 0x01;
    pub const AUTHENTICATE: u8 = 0x02;
    pub const VERSION: u8 = 0x03;
}

/// Parsed CTAP1 registration response.
#[derive(Debug)]
pub struct RegistrationData {
    pub public_key: Vec<u8>,
    pub key_handle: Vec<u8>,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

impl RegistrationData {
    /// Parse from binary response data.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ApduError> {
        if data.is_empty() || data[0] != 0x05 {
            return Err(ApduError::new(0, b"Reserved byte != 0x05".to_vec()));
        }

        let public_key = data[1..66].to_vec();
        let kh_len = data[66] as usize;
        let kh_end = 67 + kh_len;
        let key_handle = data[67..kh_end].to_vec();

        // Parse DER certificate
        let mut off = kh_end;
        let cert_tag = data[off];
        off += 1;
        let first_len = data[off] as usize;
        off += 1;

        let cert_len;
        let cert_header_len;
        if first_len > 0x80 {
            let n_bytes = first_len - 0x80;
            let mut len_val = 0usize;
            for i in 0..n_bytes {
                len_val = (len_val << 8) | (data[off + i] as usize);
            }
            cert_len = len_val;
            cert_header_len = 2 + n_bytes; // tag + first_len_byte + n extra bytes
            let _ = off + n_bytes; // consumed by cert slice below
        } else {
            cert_len = first_len;
            cert_header_len = 2; // tag + len byte
        }

        let cert_start = kh_end;
        let cert_end = cert_start + cert_header_len + cert_len;
        let certificate = data[cert_start..cert_end].to_vec();
        let _ = cert_tag; // Used implicitly in the slice

        let signature = data[cert_end..].to_vec();

        Ok(Self {
            public_key,
            key_handle,
            certificate,
            signature,
        })
    }
}

/// Parsed CTAP1 authentication response.
#[derive(Debug)]
pub struct SignatureData {
    pub user_presence: u8,
    pub counter: u32,
    pub signature: Vec<u8>,
}

impl SignatureData {
    /// Parse from binary response data.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            user_presence: data[0],
            counter: u32::from_be_bytes([data[1], data[2], data[3], data[4]]),
            signature: data[5..].to_vec(),
        }
    }
}

/// CTAP1/U2F protocol implementation.
pub struct Ctap1<'a> {
    device: &'a dyn CtapDevice,
}

impl<'a> Ctap1<'a> {
    pub fn new(device: &'a dyn CtapDevice) -> Self {
        Self { device }
    }

    /// Pack and send an APDU, return the response data.
    pub fn send_apdu(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, ApduError> {
        let mut apdu_buf = Vec::with_capacity(7 + data.len() + 2);
        apdu_buf.push(cla);
        apdu_buf.push(ins);
        apdu_buf.push(p1);
        apdu_buf.push(p2);
        // Extended length encoding
        apdu_buf.push(0);
        apdu_buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        apdu_buf.extend_from_slice(data);
        // Le = 0x0000
        apdu_buf.push(0);
        apdu_buf.push(0);

        let response = self
            .device
            .call(cmd::MSG, &apdu_buf, &mut |_| {})
            .map_err(|e| ApduError::new(0, e.to_string().into_bytes()))?;

        if response.len() < 2 {
            return Err(ApduError::new(0, b"Response too short".to_vec()));
        }

        let status_offset = response.len() - 2;
        let status = u16::from_be_bytes([response[status_offset], response[status_offset + 1]]);
        let resp_data = response[..status_offset].to_vec();

        if status != apdu::OK {
            return Err(ApduError::new(status, resp_data));
        }

        Ok(resp_data)
    }

    /// Get the U2F version string.
    pub fn get_version(&self) -> Result<String, ApduError> {
        let data = self.send_apdu(0, ins::VERSION, 0, 0, b"")?;
        String::from_utf8(data).map_err(|e| ApduError::new(0, e.to_string().into_bytes()))
    }

    /// Register a new U2F credential.
    pub fn register(
        &self,
        client_param: &[u8],
        app_param: &[u8],
    ) -> Result<RegistrationData, ApduError> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(client_param);
        data.extend_from_slice(app_param);

        let response = self.send_apdu(0, ins::REGISTER, 0, 0, &data)?;
        RegistrationData::from_bytes(&response)
    }

    /// Authenticate with a previously registered credential.
    pub fn authenticate(
        &self,
        client_param: &[u8],
        app_param: &[u8],
        key_handle: &[u8],
        check_only: bool,
    ) -> Result<SignatureData, ApduError> {
        let mut data = Vec::with_capacity(65 + key_handle.len());
        data.extend_from_slice(client_param);
        data.extend_from_slice(app_param);
        data.push(key_handle.len() as u8);
        data.extend_from_slice(key_handle);

        let p1 = if check_only { 0x07 } else { 0x03 };
        let response = self.send_apdu(0, ins::AUTHENTICATE, p1, 0, &data)?;
        Ok(SignatureData::from_bytes(&response))
    }
}
