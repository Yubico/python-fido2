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

//! PC/SC transport for communicating with FIDO devices over NFC.

use pcsc::{Card, Context, Protocols, Scope, ShareMode};
use std::ffi::CString;

use crate::ctap::{self, CtapDevice, CtapError};
use fido2_server::log_traffic;

const AID_FIDO: &[u8] = b"\xa0\x00\x00\x06\x47\x2f\x00\x01";
const SW_SUCCESS: (u8, u8) = (0x90, 0x00);
const SW_UPDATE: (u8, u8) = (0x91, 0x00);
const SW1_MORE_DATA: u8 = 0x61;

#[derive(Debug, thiserror::Error)]
pub enum PcscError {
    #[error("PC/SC error: {0}")]
    Pcsc(#[from] pcsc::Error),
    #[error("Invalid reader name")]
    InvalidReaderName,
    #[error("Connection is closed")]
    ConnectionClosed,
}

/// List available PC/SC reader names.
pub fn list_readers() -> Result<Vec<String>, PcscError> {
    let ctx = Context::establish(Scope::User)?;
    let len = ctx.list_readers_len()?;
    let mut buf = vec![0u8; len];
    let names: Vec<String> = ctx
        .list_readers(&mut buf)?
        .map(|r| r.to_string_lossy().into_owned())
        .collect();
    Ok(names)
}

/// A connection to a smart card via PC/SC.
pub struct PcscConnection {
    card: Option<Card>,
    reader_name: String,
}

impl PcscConnection {
    /// Connect to a reader, optionally using exclusive mode.
    pub fn new(reader_name: &str, exclusive: bool) -> Result<Self, PcscError> {
        log_traffic!("Opening PCSC connection to '{}'", reader_name);
        let ctx = Context::establish(Scope::User)?;
        let reader = CString::new(reader_name).map_err(|_| PcscError::InvalidReaderName)?;
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        let card = ctx.connect(&reader, share_mode, Protocols::ANY)?;
        log_traffic!("PCSC connection opened to '{}'", reader_name);
        Ok(Self {
            card: Some(card),
            reader_name: reader_name.to_owned(),
        })
    }

    /// Get the ATR (Answer-To-Reset) of the connected card.
    pub fn get_atr(&self) -> Result<Vec<u8>, PcscError> {
        let card = self.card.as_ref().ok_or(PcscError::ConnectionClosed)?;
        Ok(card.get_attribute_owned(pcsc::Attribute::AtrString)?)
    }

    /// Transmit an APDU command and return the full response bytes
    /// (including the status word).
    pub fn transmit(&self, apdu: &[u8]) -> Result<Vec<u8>, PcscError> {
        let card = self.card.as_ref().ok_or(PcscError::ConnectionClosed)?;
        log_traffic!("SEND: {}", fido2_server::logging::hex_encode(apdu));
        let mut resp_buf = vec![0u8; 65538];
        let resp = card.transmit(apdu, &mut resp_buf)?;
        let result = resp.to_vec();
        log_traffic!("RECV: {}", fido2_server::logging::hex_encode(&result));
        Ok(result)
    }

    /// Disconnect from the card.
    pub fn disconnect(&mut self) -> Result<(), PcscError> {
        if let Some(card) = self.card.take() {
            log_traffic!("Closing PCSC connection to '{}'", self.reader_name);
            card.disconnect(pcsc::Disposition::ResetCard)
                .map_err(|(_, e)| PcscError::Pcsc(e))?;
        }
        Ok(())
    }

    /// Connect (or reconnect) to the card.
    pub fn connect(&mut self, exclusive: bool) -> Result<(), PcscError> {
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        if let Some(card) = self.card.as_mut() {
            card.reconnect(share_mode, Protocols::ANY, pcsc::Disposition::ResetCard)?;
        } else {
            let ctx = Context::establish(Scope::User)?;
            let reader = CString::new(self.reader_name.as_str())
                .map_err(|_| PcscError::InvalidReaderName)?;
            let card = ctx.connect(&reader, share_mode, Protocols::ANY)?;
            self.card = Some(card);
        }
        Ok(())
    }

    /// Reconnect to the card.
    pub fn reconnect(&mut self, exclusive: bool) -> Result<(), PcscError> {
        let card = self.card.as_mut().ok_or(PcscError::ConnectionClosed)?;
        let share_mode = if exclusive {
            ShareMode::Exclusive
        } else {
            ShareMode::Shared
        };
        card.reconnect(share_mode, Protocols::ANY, pcsc::Disposition::ResetCard)?;
        Ok(())
    }
}

impl Drop for PcscConnection {
    fn drop(&mut self) {
        let _ = self.disconnect();
    }
}

/// CTAP device over NFC using PC/SC transport.
///
/// Implements the NFCCTAP protocol: FIDO commands are framed as ISO 7816 APDUs
/// with short APDU chaining for large payloads, and keepalive polling via
/// NFCCTAP_GETRESPONSE.
pub struct CtapPcscDevice {
    conn: PcscConnection,
    capabilities: u8,
}

impl CtapPcscDevice {
    /// Open a CTAP device on the given PC/SC reader.
    ///
    /// Selects the FIDO applet and probes for CTAP2 support.
    pub fn open(mut conn: PcscConnection) -> Result<Self, CtapError> {
        conn.connect(false)
            .map_err(|e| CtapError::TransportError(e.to_string()))?;

        let mut dev = Self {
            conn,
            capabilities: 0,
        };
        dev.select()?;

        // Probe for CTAP2 by calling GET_INFO (0x04)
        match dev.call_cbor(b"\x04", &mut |_| {}, None) {
            Ok(_) => dev.capabilities |= ctap::capability::CBOR,
            Err(_) => {
                if dev.capabilities == 0 {
                    return Err(CtapError::TransportError("Unsupported device".to_string()));
                }
            }
        }

        Ok(dev)
    }

    /// Get a reference to the underlying PC/SC connection.
    pub fn connection(&self) -> &PcscConnection {
        &self.conn
    }

    /// Get a mutable reference to the underlying PC/SC connection.
    pub fn connection_mut(&mut self) -> &mut PcscConnection {
        &mut self.conn
    }

    /// Consume the device and return the underlying connection.
    pub fn into_connection(self) -> PcscConnection {
        self.conn
    }

    fn transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u8, u8), CtapError> {
        let resp = self
            .conn
            .transmit(apdu)
            .map_err(|e| CtapError::TransportError(e.to_string()))?;
        if resp.len() < 2 {
            return Err(CtapError::InvalidResponse("Response too short".to_string()));
        }
        let sw1 = resp[resp.len() - 2];
        let sw2 = resp[resp.len() - 1];
        let data = resp[..resp.len() - 2].to_vec();
        Ok((data, sw1, sw2))
    }

    fn select(&mut self) -> Result<(), CtapError> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, AID_FIDO.len() as u8];
        apdu.extend_from_slice(AID_FIDO);
        let (resp, sw1, sw2) = self.chain_apdus(0x00, 0xA4, 0x04, 0x00, AID_FIDO)?;
        if (sw1, sw2) != SW_SUCCESS {
            return Err(CtapError::TransportError(format!(
                "FIDO applet selection failed: SW={sw1:02X}{sw2:02X}"
            )));
        }
        if resp == b"U2F_V2" {
            self.capabilities |= ctap::capability::NMSG;
        }
        Ok(())
    }

    /// Send a chained short APDU and collect the full response.
    fn chain_apdus(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<(Vec<u8>, u8, u8), CtapError> {
        let mut remaining = data;

        // Chain long data in 250-byte chunks
        while remaining.len() > 250 {
            let (chunk, rest) = remaining.split_at(250);
            remaining = rest;
            let mut apdu = vec![0x10 | cla, ins, p1, p2, chunk.len() as u8];
            apdu.extend_from_slice(chunk);
            let (_resp, sw1, sw2) = self.transmit(&apdu)?;
            if (sw1, sw2) != SW_SUCCESS {
                return Ok((_resp, sw1, sw2));
            }
        }

        // Final (or only) chunk
        let mut apdu = vec![cla, ins, p1, p2];
        if !remaining.is_empty() {
            apdu.push(remaining.len() as u8);
            apdu.extend_from_slice(remaining);
        }
        apdu.push(0x00); // Le
        let (mut resp, mut sw1, mut sw2) = self.transmit(&apdu)?;

        // Collect chained response (SW1=0x61 means more data)
        while sw1 == SW1_MORE_DATA {
            let get_resp = vec![0x00, 0xC0, 0x00, 0x00, sw2];
            let (more, s1, s2) = self.transmit(&get_resp)?;
            resp.extend_from_slice(&more);
            sw1 = s1;
            sw2 = s2;
        }

        Ok((resp, sw1, sw2))
    }

    fn call_apdu(&self, apdu: &[u8]) -> Result<Vec<u8>, CtapError> {
        // Parse the APDU header
        if apdu.len() < 4 {
            return Err(CtapError::InvalidResponse("APDU too short".to_string()));
        }
        let (cla, ins, p1, p2) = (apdu[0], apdu[1], apdu[2], apdu[3]);
        let data = if apdu.len() > 5 {
            &apdu[5..5 + apdu[4] as usize]
        } else {
            &[]
        };

        let (resp, sw1, sw2) = self.chain_apdus(cla, ins, p1, p2, data)?;
        let mut result = resp;
        result.push(sw1);
        result.push(sw2);
        Ok(result)
    }

    fn call_cbor(
        &self,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        // NFCCTAP_MSG: CLA=0x80, INS=0x10, P1=0x80 (use NFCCTAP_GETRESPONSE), P2=0x00
        let (mut resp, mut sw1, mut sw2) = self.chain_apdus(0x80, 0x10, 0x80, 0x00, data)?;

        // NFCCTAP_GETRESPONSE loop for keepalive
        while (sw1, sw2) == SW_UPDATE {
            if !resp.is_empty() {
                on_keepalive(resp[0]);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            let p1 = if cancel.is_some_and(|f| f()) {
                0x11 // Cancel
            } else {
                0x00
            };
            let result = self.chain_apdus(0x80, 0x11, p1, 0x00, &[])?;
            resp = result.0;
            sw1 = result.1;
            sw2 = result.2;
        }

        if (sw1, sw2) != SW_SUCCESS {
            return Err(CtapError::TransportError(format!(
                "NFCCTAP error: SW={sw1:02X}{sw2:02X}"
            )));
        }

        Ok(resp)
    }
}

impl CtapDevice for CtapPcscDevice {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        match cmd {
            ctap::cmd::CBOR => self.call_cbor(data, on_keepalive, cancel),
            ctap::cmd::MSG => self.call_apdu(data),
            _ => Err(CtapError::StatusError(ctap::CtapStatus::InvalidCommand)),
        }
    }

    fn capabilities(&self) -> u8 {
        self.capabilities
    }

    fn close(&mut self) {
        let _ = self.conn.disconnect();
    }
}
