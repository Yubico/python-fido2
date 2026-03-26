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

//! CTAP2 Credential Management API.

use crate::cbor::{self, Value};
use crate::ctap::{CtapError, CtapStatus};
use crate::ctap2::{ctap2_cmd, Ctap2};
use crate::pin::PinProtocol;

/// Sub-command identifiers for credential management.
pub mod cmd {
    pub const GET_CREDS_METADATA: u32 = 0x01;
    pub const ENUMERATE_RPS_BEGIN: u32 = 0x02;
    pub const ENUMERATE_RPS_NEXT: u32 = 0x03;
    pub const ENUMERATE_CREDS_BEGIN: u32 = 0x04;
    pub const ENUMERATE_CREDS_NEXT: u32 = 0x05;
    pub const DELETE_CREDENTIAL: u32 = 0x06;
    pub const UPDATE_USER_INFO: u32 = 0x07;
}

/// Parameter keys for credential management sub-commands.
pub mod param {
    pub const RP_ID_HASH: i64 = 0x01;
    pub const CREDENTIAL_ID: i64 = 0x02;
    pub const USER: i64 = 0x03;
}

/// Result keys for credential management responses.
pub mod result {
    pub const EXISTING_CRED_COUNT: i64 = 0x01;
    pub const MAX_REMAINING_COUNT: i64 = 0x02;
    pub const RP: i64 = 0x03;
    pub const RP_ID_HASH: i64 = 0x04;
    pub const TOTAL_RPS: i64 = 0x05;
    pub const USER: i64 = 0x06;
    pub const CREDENTIAL_ID: i64 = 0x07;
    pub const PUBLIC_KEY: i64 = 0x08;
    pub const TOTAL_CREDENTIALS: i64 = 0x09;
    pub const CRED_PROTECT: i64 = 0x0A;
    pub const LARGE_BLOB_KEY: i64 = 0x0B;
    pub const THIRD_PARTY_PAYMENT: i64 = 0x0C;
}

/// Credential Management API.
pub struct CredentialManagement<'a> {
    ctap: &'a Ctap2<'a>,
    protocol: &'a PinProtocol,
    pin_uv_token: &'a [u8],
    cmd_byte: u8,
}

impl<'a> CredentialManagement<'a> {
    /// Create a new CredentialManagement instance.
    pub fn new(
        ctap: &'a Ctap2<'a>,
        protocol: &'a PinProtocol,
        pin_uv_token: &'a [u8],
    ) -> Result<Self, CtapError> {
        let info = ctap.info();
        let cmd_byte = if info.options.get("credMgmt") == Some(&true) {
            ctap2_cmd::CREDENTIAL_MGMT
        } else if info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && info.options.get("credentialMgmtPreview") == Some(&true)
        {
            ctap2_cmd::CREDENTIAL_MGMT_PRE
        } else {
            return Err(CtapError::InvalidResponse(
                "Authenticator does not support Credential Management".to_string(),
            ));
        };
        Ok(Self {
            ctap,
            protocol,
            pin_uv_token,
            cmd_byte,
        })
    }

    /// Create without validation (for PyO3 wrappers).
    pub fn from_parts(
        ctap: &'a Ctap2<'a>,
        protocol: &'a PinProtocol,
        pin_uv_token: &'a [u8],
        cmd_byte: u8,
    ) -> Self {
        Self { ctap, protocol, pin_uv_token, cmd_byte }
    }

    fn _call(
        &self,
        sub_cmd: u32,
        params: Option<Value>,
        auth: bool,
    ) -> Result<Value, CtapError> {
        let (pin_uv_protocol, pin_uv_param) = if auth {
            let mut msg = vec![(sub_cmd & 0xFF) as u8];
            if let Some(ref p) = params {
                msg.extend_from_slice(&cbor::encode(p));
            }
            (
                Some(Value::Int(self.protocol.version() as i64)),
                Some(Value::Bytes(
                    self.protocol.authenticate(self.pin_uv_token, &msg),
                )),
            )
        } else {
            (None, None)
        };
        self.ctap.credential_mgmt(
            self.cmd_byte,
            Value::Int(sub_cmd as i64),
            params,
            pin_uv_protocol,
            pin_uv_param,
            &mut |_| {},
        )
    }

    /// Get credentials metadata.
    pub fn get_metadata(&self) -> Result<Value, CtapError> {
        self._call(cmd::GET_CREDS_METADATA, None, true)
    }

    /// Start RP enumeration.
    pub fn enumerate_rps_begin(&self) -> Result<Value, CtapError> {
        self._call(cmd::ENUMERATE_RPS_BEGIN, None, true)
    }

    /// Get the next RP.
    pub fn enumerate_rps_next(&self) -> Result<Value, CtapError> {
        self._call(cmd::ENUMERATE_RPS_NEXT, None, false)
    }

    /// Enumerate all RPs.
    pub fn enumerate_rps(&self) -> Result<Vec<Value>, CtapError> {
        let first = match self.enumerate_rps_begin() {
            Ok(v) => v,
            Err(CtapError::StatusError(CtapStatus::NoCredentials)) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let total = cbor_map_get_int(&first, result::TOTAL_RPS).unwrap_or(0) as usize;
        if total == 0 {
            return Ok(vec![]);
        }
        let mut results = vec![first];
        for _ in 1..total {
            results.push(self.enumerate_rps_next()?);
        }
        Ok(results)
    }

    /// Start credential enumeration for an RP.
    pub fn enumerate_creds_begin(&self, rp_id_hash: &[u8]) -> Result<Value, CtapError> {
        let params = Value::Map(vec![(
            Value::Int(param::RP_ID_HASH),
            Value::Bytes(rp_id_hash.to_vec()),
        )]);
        self._call(cmd::ENUMERATE_CREDS_BEGIN, Some(params), true)
    }

    /// Get the next credential.
    pub fn enumerate_creds_next(&self) -> Result<Value, CtapError> {
        self._call(cmd::ENUMERATE_CREDS_NEXT, None, false)
    }

    /// Enumerate all credentials for an RP.
    pub fn enumerate_creds(&self, rp_id_hash: &[u8]) -> Result<Vec<Value>, CtapError> {
        let first = match self.enumerate_creds_begin(rp_id_hash) {
            Ok(v) => v,
            Err(CtapError::StatusError(CtapStatus::NoCredentials)) => return Ok(vec![]),
            Err(e) => return Err(e),
        };
        let total = cbor_map_get_int(&first, result::TOTAL_CREDENTIALS).unwrap_or(1) as usize;
        let mut results = vec![first];
        for _ in 1..total {
            results.push(self.enumerate_creds_next()?);
        }
        Ok(results)
    }

    /// Delete a credential.
    pub fn delete_cred(&self, cred_id: Value) -> Result<(), CtapError> {
        let params = Value::Map(vec![(Value::Int(param::CREDENTIAL_ID), cred_id)]);
        self._call(cmd::DELETE_CREDENTIAL, Some(params), true)?;
        Ok(())
    }

    /// Update user info for a credential.
    pub fn update_user_info(&self, cred_id: Value, user: Value) -> Result<(), CtapError> {
        let params = Value::Map(vec![
            (Value::Int(param::CREDENTIAL_ID), cred_id),
            (Value::Int(param::USER), user),
        ]);
        self._call(cmd::UPDATE_USER_INFO, Some(params), true)?;
        Ok(())
    }
}

fn cbor_map_get_int(val: &Value, key: i64) -> Option<i64> {
    match val {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
            .and_then(|(_, v)| v.as_int()),
        _ => None,
    }
}
