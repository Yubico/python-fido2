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

//! CTAP2.1 Large Blobs API.

use crate::cbor::{self, Value};
use crate::ctap::CtapError;
use crate::ctap2::Ctap2;
use crate::pin::PinProtocol;
use crate::utils;

/// Large Blobs API.
pub struct LargeBlobs<'a> {
    ctap: &'a Ctap2<'a>,
    max_fragment_length: usize,
    protocol: Option<&'a PinProtocol>,
    pin_uv_token: Option<&'a [u8]>,
}

impl<'a> LargeBlobs<'a> {
    /// Create a new LargeBlobs instance.
    pub fn new(
        ctap: &'a Ctap2<'a>,
        protocol: Option<&'a PinProtocol>,
        pin_uv_token: Option<&'a [u8]>,
    ) -> Result<Self, CtapError> {
        let info = ctap.info();
        if info.options.get("largeBlobs") != Some(&true) {
            return Err(CtapError::InvalidResponse(
                "Authenticator does not support LargeBlobs".to_string(),
            ));
        }
        let max_fragment_length = info.max_msg_size.saturating_sub(64);
        Ok(Self {
            ctap,
            max_fragment_length,
            protocol,
            pin_uv_token,
        })
    }

    /// Read the entire large blob array.
    pub fn read_blob_array(&self) -> Result<Vec<Value>, CtapError> {
        let mut offset: u64 = 0;
        let mut buf = Vec::new();
        loop {
            let resp = self.ctap.large_blobs(
                offset,
                Some(self.max_fragment_length as u64),
                None,
                None,
                None,
                None,
                &mut |_| {},
            )?;
            let fragment = cbor_map_get_bytes(&resp, 1).unwrap_or_default();
            let frag_len = fragment.len();
            buf.extend_from_slice(&fragment);
            if frag_len < self.max_fragment_length {
                break;
            }
            offset += frag_len as u64;
        }

        if buf.len() < 16 {
            return Ok(vec![]);
        }

        let (data, check) = buf.split_at(buf.len() - 16);
        let hash = utils::sha256(data);
        if check != &hash[..16] {
            return Ok(vec![]);
        }

        match cbor::decode(data) {
            Ok(Value::Array(arr)) => Ok(arr),
            _ => Ok(vec![]),
        }
    }

    /// Write the entire large blob array.
    pub fn write_blob_array(&self, blob_array: &[Value]) -> Result<(), CtapError> {
        let data = cbor::encode(&Value::Array(blob_array.to_vec()));
        let hash = utils::sha256(&data);
        let mut full_data = data;
        full_data.extend_from_slice(&hash[..16]);

        let size = full_data.len();
        let mut offset: u64 = 0;

        while (offset as usize) < size {
            let end = std::cmp::min(size, offset as usize + self.max_fragment_length);
            let fragment = &full_data[offset as usize..end];

            let (pin_uv_param, pin_uv_protocol) =
                if let (Some(protocol), Some(token)) = (self.protocol, self.pin_uv_token) {
                    let mut msg = vec![0xFFu8; 32];
                    msg.extend_from_slice(&[0x0C, 0x00]);
                    msg.extend_from_slice(&(offset as u32).to_le_bytes());
                    msg.extend_from_slice(&utils::sha256(fragment));
                    let param = protocol.authenticate(token, &msg);
                    (Some(param), Some(protocol.version()))
                } else {
                    (None, None)
                };

            self.ctap.large_blobs(
                offset,
                None,
                Some(fragment),
                if offset == 0 { Some(size as u64) } else { None },
                pin_uv_param.as_deref(),
                pin_uv_protocol,
                &mut |_| {},
            )?;

            offset += (end - offset as usize) as u64;
        }

        Ok(())
    }

    /// Get a single blob by key.
    pub fn get_blob(&self, large_blob_key: &[u8]) -> Result<Option<Vec<u8>>, CtapError> {
        let entries = self.read_blob_array()?;
        for entry in &entries {
            if let Ok(data) = lb_unpack(large_blob_key, entry) {
                if let Ok(decompressed) = decompress(&data.0) {
                    if decompressed.len() == data.1 {
                        return Ok(Some(decompressed));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Store a blob (or delete if data is None).
    pub fn put_blob(
        &self,
        large_blob_key: &[u8],
        data: Option<&[u8]>,
    ) -> Result<(), CtapError> {
        let mut modified = data.is_some();
        let mut entries = Vec::new();

        for entry in self.read_blob_array()? {
            if lb_unpack(large_blob_key, &entry).is_ok() {
                modified = true;
            } else {
                entries.push(entry);
            }
        }

        if let Some(data) = data {
            entries.push(lb_pack(large_blob_key, data)?);
        }

        if modified {
            self.write_blob_array(&entries)?;
        }

        Ok(())
    }

    /// Delete blob(s) for a key.
    pub fn delete_blob(&self, large_blob_key: &[u8]) -> Result<(), CtapError> {
        self.put_blob(large_blob_key, None)
    }
}

fn lb_ad(orig_size: usize) -> Vec<u8> {
    let mut ad = b"blob".to_vec();
    ad.extend_from_slice(&(orig_size as u64).to_le_bytes());
    ad
}

fn lb_pack(key: &[u8], data: &[u8]) -> Result<Value, CtapError> {
    let orig_size = data.len();
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| {
        CtapError::InvalidResponse("Failed to generate random nonce".to_string())
    })?;

    let compressed = compress(data)
        .map_err(|_| CtapError::InvalidResponse("Compression failed".to_string()))?;
    let ciphertext = utils::aes_gcm_encrypt(key, &nonce, &compressed, &lb_ad(orig_size))
        .map_err(|e| CtapError::InvalidResponse(e.to_string()))?;

    Ok(Value::Map(vec![
        (Value::Int(1), Value::Bytes(ciphertext)),
        (Value::Int(2), Value::Bytes(nonce.to_vec())),
        (Value::Int(3), Value::Int(orig_size as i64)),
    ]))
}

fn lb_unpack(key: &[u8], entry: &Value) -> Result<(Vec<u8>, usize), String> {
    let map = match entry {
        Value::Map(m) => m,
        _ => return Err("Invalid entry".to_string()),
    };

    let get = |k: i64| -> Option<&Value> {
        map.iter()
            .find(|(key, _)| matches!(key, Value::Int(n) if *n == k))
            .map(|(_, v)| v)
    };

    let ciphertext = get(1)
        .and_then(|v| v.as_bytes())
        .ok_or("Invalid entry")?;
    let nonce = get(2)
        .and_then(|v| v.as_bytes())
        .ok_or("Invalid entry")?;
    let orig_size = get(3)
        .and_then(|v| v.as_int())
        .ok_or("Invalid entry")? as usize;

    let compressed =
        utils::aes_gcm_decrypt(key, nonce, ciphertext, &lb_ad(orig_size))
            .map_err(|_| "Wrong key".to_string())?;

    Ok((compressed, orig_size))
}

fn compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Write;
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn decompress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result)?;
    Ok(result)
}

fn cbor_map_get_bytes(val: &Value, key: i64) -> Option<Vec<u8>> {
    match val {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
            .and_then(|(_, v)| v.as_bytes().map(|b| b.to_vec())),
        _ => None,
    }
}
