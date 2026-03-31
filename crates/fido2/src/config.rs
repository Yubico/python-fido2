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

//! CTAP2.1 Authenticator Config API.

use crate::cbor::{self, Value};
use crate::ctap::CtapError;
use crate::ctap2::Ctap2;
use crate::pin::PinProtocol;

/// Config sub-commands.
pub mod cmd {
    pub const ENABLE_ENTERPRISE_ATT: u32 = 0x01;
    pub const TOGGLE_ALWAYS_UV: u32 = 0x02;
    pub const SET_MIN_PIN_LENGTH: u32 = 0x03;
    pub const VENDOR_PROTOTYPE: u32 = 0xFF;
}

/// Config parameter keys.
pub mod param {
    pub const NEW_MIN_PIN_LENGTH: i64 = 0x01;
    pub const MIN_PIN_LENGTH_RPIDS: i64 = 0x02;
    pub const FORCE_CHANGE_PIN: i64 = 0x03;
    pub const PIN_COMPLEXITY_POLICY: i64 = 0x04;
}

/// Authenticator Config API.
pub struct Config<'a> {
    ctap: &'a Ctap2<'a>,
    protocol: Option<&'a PinProtocol>,
    pin_uv_token: Option<&'a [u8]>,
}

impl<'a> Config<'a> {
    /// Create a new Config instance.
    pub fn new(
        ctap: &'a Ctap2<'a>,
        protocol: Option<&'a PinProtocol>,
        pin_uv_token: Option<&'a [u8]>,
    ) -> Result<Self, CtapError> {
        let info = ctap.info();
        if info.options.get("authnrCfg") != Some(&true) {
            return Err(CtapError::InvalidResponse(
                "Authenticator does not support Config".to_string(),
            ));
        }
        Ok(Self {
            ctap,
            protocol,
            pin_uv_token,
        })
    }

    /// Create without validation (for PyO3 wrappers).
    pub fn from_parts(
        ctap: &'a Ctap2<'a>,
        protocol: Option<&'a PinProtocol>,
        pin_uv_token: Option<&'a [u8]>,
    ) -> Self {
        Self {
            ctap,
            protocol,
            pin_uv_token,
        }
    }

    fn _call(&self, sub_cmd: u32, params: Option<Value>) -> Result<Value, CtapError> {
        let (pin_uv_protocol, pin_uv_param) =
            if let (Some(protocol), Some(token)) = (self.protocol, self.pin_uv_token) {
                let mut msg = vec![0xFFu8; 32];
                msg.push(0x0D);
                msg.push(sub_cmd as u8);
                if let Some(ref p) = params {
                    msg.extend_from_slice(&cbor::encode(p));
                }
                (
                    Some(Value::Int(protocol.version() as i64)),
                    Some(Value::Bytes(protocol.authenticate(token, &msg))),
                )
            } else {
                (None, None)
            };
        self.ctap.config(
            Value::Int(sub_cmd as i64),
            params,
            pin_uv_protocol,
            pin_uv_param,
            &mut |_| {},
            None,
        )
    }

    /// Enable enterprise attestation.
    pub fn enable_enterprise_attestation(&self) -> Result<(), CtapError> {
        self._call(cmd::ENABLE_ENTERPRISE_ATT, None)?;
        Ok(())
    }

    /// Toggle always UV.
    pub fn toggle_always_uv(&self) -> Result<(), CtapError> {
        self._call(cmd::TOGGLE_ALWAYS_UV, None)?;
        Ok(())
    }

    /// Set minimum PIN length.
    pub fn set_min_pin_length(
        &self,
        min_pin_length: Option<u32>,
        rp_ids: Option<&[&str]>,
        force_change_pin: bool,
    ) -> Result<(), CtapError> {
        let mut entries = vec![(
            Value::Int(param::FORCE_CHANGE_PIN),
            Value::Bool(force_change_pin),
        )];
        if let Some(len) = min_pin_length {
            entries.push((
                Value::Int(param::NEW_MIN_PIN_LENGTH),
                Value::Int(len as i64),
            ));
        }
        if let Some(ids) = rp_ids {
            entries.push((
                Value::Int(param::MIN_PIN_LENGTH_RPIDS),
                Value::Array(ids.iter().map(|s| Value::Text(s.to_string())).collect()),
            ));
        }
        self._call(cmd::SET_MIN_PIN_LENGTH, Some(Value::Map(entries)))?;
        Ok(())
    }
}
