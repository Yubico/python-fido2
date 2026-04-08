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

//! CTAP2 protocol implementation.
//!
//! Provides the [`Ctap2`] struct for communicating with FIDO2 authenticators,
//! along with response types [`Info`], [`AttestationResponse`], and [`AssertionResponse`].

use std::collections::BTreeMap;

use crate::ctap::{CtapDevice, CtapError, CtapStatus, capability, cmd};
use fido2_server::cbor::{self, Value};
use fido2_server::webauthn::{Aaguid, AuthenticatorData, WebauthnError};

/// CTAP2 command codes.
pub mod ctap2_cmd {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const BIO_ENROLLMENT: u8 = 0x09;
    pub const CREDENTIAL_MGMT: u8 = 0x0A;
    pub const SELECTION: u8 = 0x0B;
    pub const LARGE_BLOBS: u8 = 0x0C;
    pub const CONFIG: u8 = 0x0D;
    pub const BIO_ENROLLMENT_PRE: u8 = 0x40;
    pub const CREDENTIAL_MGMT_PRE: u8 = 0x41;
}

/// Helper: build a CBOR map from positional arguments, skipping None values.
/// Keys are 1-based integers.
fn args_map(params: &[Option<Value>]) -> Value {
    let mut entries = Vec::new();
    for (i, v) in params.iter().enumerate() {
        if let Some(val) = v {
            entries.push((Value::Int((i + 1) as i64), val.clone()));
        }
    }
    Value::Map(entries)
}

/// Authenticator information returned by GET_INFO.
#[derive(Debug, Clone)]
pub struct Info {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: Aaguid,
    pub options: BTreeMap<String, bool>,
    pub max_msg_size: usize,
    pub pin_uv_protocols: Vec<u32>,
    pub max_creds_in_list: usize,
    pub max_cred_id_length: usize,
    pub transports: Vec<String>,
    pub algorithms: Vec<BTreeMap<String, Value>>,
    pub max_large_blob: usize,
    pub force_pin_change: bool,
    pub min_pin_length: usize,
    pub firmware_version: u64,
    pub max_cred_blob_length: usize,
    pub max_rpids_for_min_pin: usize,
    pub preferred_platform_uv_attempts: usize,
    pub uv_modality: u32,
    pub certifications: BTreeMap<String, Value>,
    pub remaining_disc_creds: Option<u32>,
    pub vendor_prototype_config_commands: Vec<u32>,
    pub attestation_formats: Vec<String>,
    pub uv_count_since_pin: Option<u32>,
    pub long_touch_for_reset: bool,
    pub transports_for_reset: Vec<String>,
}

impl Info {
    /// Parse from a CBOR response map (integer-keyed).
    pub fn from_cbor(map: &[(Value, Value)]) -> Self {
        let get = |key: i64| -> Option<&Value> {
            map.iter()
                .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
                .map(|(_, v)| v)
        };

        let get_strings = |key: i64| -> Vec<String> {
            get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_text().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };

        let get_uint = |key: i64, default: u64| -> u64 {
            get(key)
                .and_then(|v| v.as_int())
                .map(|n| n as u64)
                .unwrap_or(default)
        };

        let get_bool = |key: i64, default: bool| -> bool {
            get(key).and_then(|v| v.as_bool()).unwrap_or(default)
        };

        let aaguid = get(3)
            .and_then(|v| v.as_bytes())
            .and_then(|b| Aaguid::from_slice(b).ok())
            .unwrap_or(Aaguid::NONE);

        let options = get(4)
            .and_then(|v| match v {
                Value::Map(entries) => {
                    let mut map = BTreeMap::new();
                    for (k, v) in entries {
                        if let (Some(key), Some(val)) = (k.as_text(), v.as_bool()) {
                            map.insert(key.to_string(), val);
                        }
                    }
                    Some(map)
                }
                _ => None,
            })
            .unwrap_or_default();

        let pin_uv_protocols = get(6)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_int().map(|n| n as u32))
                    .collect()
            })
            .unwrap_or_default();

        let algorithms = get(10)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| match v {
                        Value::Map(entries) => {
                            let mut m = BTreeMap::new();
                            for (k, v) in entries {
                                if let Some(key) = k.as_text() {
                                    m.insert(key.to_string(), v.clone());
                                }
                            }
                            Some(m)
                        }
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let certifications = get(19)
            .and_then(|v| match v {
                Value::Map(entries) => {
                    let mut map = BTreeMap::new();
                    for (k, v) in entries {
                        if let Some(key) = k.as_text() {
                            map.insert(key.to_string(), v.clone());
                        }
                    }
                    Some(map)
                }
                _ => None,
            })
            .unwrap_or_default();

        let remaining_disc_creds = get(20).and_then(|v| v.as_int().map(|n| n as u32));

        let vendor_prototype_config_commands = get(21)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_int().map(|n| n as u32))
                    .collect()
            })
            .unwrap_or_default();

        let attestation_formats = {
            let fmts = get_strings(22);
            if fmts.is_empty() {
                vec!["packed".to_string()]
            } else {
                fmts
            }
        };

        let uv_count_since_pin = get(23).and_then(|v| v.as_int().map(|n| n as u32));
        let long_touch_for_reset = get_bool(24, false);
        let transports_for_reset = get_strings(26);

        Info {
            versions: get_strings(1),
            extensions: get_strings(2),
            aaguid,
            options,
            max_msg_size: get_uint(5, 1024) as usize,
            pin_uv_protocols,
            max_creds_in_list: get_uint(7, 0) as usize,
            max_cred_id_length: get_uint(8, 0) as usize,
            transports: get_strings(9),
            algorithms,
            max_large_blob: get_uint(11, 0) as usize,
            force_pin_change: get_bool(12, false),
            min_pin_length: get_uint(13, 4) as usize,
            firmware_version: get_uint(14, 0),
            max_cred_blob_length: get_uint(15, 0) as usize,
            max_rpids_for_min_pin: get_uint(16, 0) as usize,
            preferred_platform_uv_attempts: get_uint(17, 0) as usize,
            uv_modality: get_uint(18, 0) as u32,
            certifications,
            remaining_disc_creds,
            vendor_prototype_config_commands,
            attestation_formats,
            uv_count_since_pin,
            long_touch_for_reset,
            transports_for_reset,
        }
    }
}

/// Attestation response from makeCredential.
#[derive(Debug, Clone)]
pub struct AttestationResponse {
    pub fmt: String,
    pub auth_data: AuthenticatorData,
    pub att_stmt: Value,
    pub ep_att: Option<bool>,
    pub large_blob_key: Option<Vec<u8>>,
    pub unsigned_extension_outputs: BTreeMap<String, Value>,
}

impl AttestationResponse {
    /// Create from CTAP1/U2F registration data.
    pub fn from_ctap1(
        app_param: &[u8],
        registration: &crate::ctap1::RegistrationData,
    ) -> Result<Self, WebauthnError> {
        let credential_data = fido2_server::webauthn::AttestedCredentialData::from_ctap1(
            &registration.key_handle,
            &registration.public_key,
        )?;

        let flags = fido2_server::webauthn::AuthenticatorDataFlags::AT
            | fido2_server::webauthn::AuthenticatorDataFlags::UP;
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(app_param);
        let auth_data =
            AuthenticatorData::create(&rp_id_hash, flags, 0, Some(&credential_data), None);

        let att_stmt = Value::Map(vec![
            (
                Value::Text("x5c".into()),
                Value::Array(vec![Value::Bytes(registration.certificate.clone())]),
            ),
            (
                Value::Text("sig".into()),
                Value::Bytes(registration.signature.clone()),
            ),
        ]);

        Ok(Self {
            fmt: "fido-u2f".into(),
            auth_data,
            att_stmt,
            ep_att: None,
            large_blob_key: None,
            unsigned_extension_outputs: BTreeMap::new(),
        })
    }

    /// Parse from a CBOR response map (integer-keyed).
    pub fn from_cbor(map: &[(Value, Value)]) -> Result<Self, WebauthnError> {
        let get = |key: i64| -> Option<&Value> {
            map.iter()
                .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
                .map(|(_, v)| v)
        };

        let fmt = get(1)
            .and_then(|v| v.as_text())
            .ok_or_else(|| WebauthnError::InvalidData("Missing fmt in attestation".into()))?
            .to_string();

        let auth_data_bytes = get(2)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| WebauthnError::InvalidData("Missing auth_data in attestation".into()))?;

        let auth_data = AuthenticatorData::from_bytes(auth_data_bytes)?;

        let att_stmt = get(3).cloned().unwrap_or(Value::Map(vec![]));

        let ep_att = get(4).and_then(|v| v.as_bool());

        let large_blob_key = get(5).and_then(|v| v.as_bytes()).map(|b| b.to_vec());

        let unsigned_extension_outputs = get(6)
            .and_then(|v| match v {
                Value::Map(entries) => {
                    let mut map = BTreeMap::new();
                    for (k, v) in entries {
                        if let Some(key) = k.as_text() {
                            map.insert(key.to_string(), v.clone());
                        }
                    }
                    Some(map)
                }
                _ => None,
            })
            .unwrap_or_default();

        Ok(Self {
            fmt,
            auth_data,
            att_stmt,
            ep_att,
            large_blob_key,
            unsigned_extension_outputs,
        })
    }
}

/// Assertion response from getAssertion.
#[derive(Debug, Clone)]
pub struct AssertionResponse {
    /// The credential used (CBOR map with "id" and "type").
    pub credential: Value,
    pub auth_data: AuthenticatorData,
    pub signature: Vec<u8>,
    pub user: Option<Value>,
    pub number_of_credentials: Option<u32>,
    pub user_selected: Option<bool>,
    pub large_blob_key: Option<Vec<u8>>,
}

impl AssertionResponse {
    /// Parse from a CBOR response map (integer-keyed).
    pub fn from_cbor(map: &[(Value, Value)]) -> Result<Self, WebauthnError> {
        let get = |key: i64| -> Option<&Value> {
            map.iter()
                .find(|(k, _)| matches!(k, Value::Int(n) if *n == key))
                .map(|(_, v)| v)
        };

        let credential = get(1)
            .cloned()
            .ok_or_else(|| WebauthnError::InvalidData("Missing credential".into()))?;

        let auth_data_bytes = get(2)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| WebauthnError::InvalidData("Missing auth_data".into()))?;

        let auth_data = AuthenticatorData::from_bytes(auth_data_bytes)?;

        let signature = get(3)
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| WebauthnError::InvalidData("Missing signature".into()))?
            .to_vec();

        let user = get(4).cloned();
        let number_of_credentials = get(5).and_then(|v| v.as_int().map(|n| n as u32));
        let user_selected = get(6).and_then(|v| v.as_bool());
        let large_blob_key = get(7).and_then(|v| v.as_bytes()).map(|b| b.to_vec());

        Ok(Self {
            credential,
            auth_data,
            signature,
            user,
            number_of_credentials,
            user_selected,
            large_blob_key,
        })
    }

    /// Create from CTAP1 authentication data.
    pub fn from_ctap1(
        app_param: &[u8],
        credential: Value,
        user_presence: u8,
        counter: u32,
        signature: &[u8],
    ) -> Self {
        use fido2_server::webauthn::AuthenticatorDataFlags;

        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(app_param);

        let flags = if user_presence & AuthenticatorDataFlags::UP.bits() != 0 {
            AuthenticatorDataFlags::UP
        } else {
            AuthenticatorDataFlags::empty()
        };

        let auth_data = AuthenticatorData::create(&rp_id_hash, flags, counter, None, None);

        Self {
            credential,
            auth_data,
            signature: signature.to_vec(),
            user: None,
            number_of_credentials: None,
            user_selected: None,
            large_blob_key: None,
        }
    }
}

/// CTAP2 protocol implementation.
pub struct Ctap2<D: CtapDevice> {
    device: D,
    strict_cbor: bool,
    max_msg_size: usize,
    info: Info,
}

impl<D: CtapDevice> Ctap2<D> {
    /// Create a new Ctap2 instance, performing initial GET_INFO.
    pub fn new(device: D, strict_cbor: bool) -> Result<Self, CtapError> {
        if device.capabilities() & capability::CBOR == 0 {
            return Err(CtapError::InvalidResponse(
                "Device does not support CTAP2".into(),
            ));
        }

        let mut ctap = Self {
            device,
            strict_cbor,
            max_msg_size: 1024,
            info: Info::from_cbor(&[]),
        };

        let info = ctap.get_info()?;
        ctap.max_msg_size = info.max_msg_size;
        ctap.info = info;

        Ok(ctap)
    }

    /// Create a Ctap2 from parts without calling get_info.
    ///
    /// Caller must call `set_info()` afterwards to set authenticator info.
    pub fn from_parts(device: D, strict_cbor: bool, max_msg_size: usize) -> Self {
        Self {
            device,
            strict_cbor,
            max_msg_size,
            info: Info::from_cbor(&[]),
        }
    }

    /// Consume the Ctap2 and return the owned device.
    pub fn into_device(self) -> D {
        self.device
    }

    /// Update cached authenticator info.
    pub fn set_info(&mut self, info: Info) {
        self.max_msg_size = info.max_msg_size;
        self.info = info;
    }

    /// Get cached authenticator info.
    pub fn info(&self) -> &Info {
        &self.info
    }

    /// Get a reference to the underlying device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Get a mutable reference to the underlying device.
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Send a CBOR command and receive the decoded response.
    pub fn send_cbor(
        &mut self,
        cmd_byte: u8,
        data: Option<&Value>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, CtapError> {
        let mut request = vec![cmd_byte];
        if let Some(val) = data {
            let encoded = val.encode();
            request.extend_from_slice(&encoded);
        }

        if request.len() > self.max_msg_size {
            return Err(CtapError::StatusError(CtapStatus::RequestTooLarge));
        }

        let response = self
            .device
            .call(cmd::CBOR, &request, on_keepalive, cancel)?;

        if response.is_empty() {
            return Err(CtapError::InvalidResponse("Empty response".into()));
        }

        let status = response[0];
        if status != 0x00 {
            return Err(CtapError::status(status));
        }

        let enc = &response[1..];
        if enc.is_empty() {
            return Ok(Value::Map(vec![]));
        }

        let decoded = cbor::decode(enc).map_err(|e| CtapError::InvalidResponse(e.to_string()))?;

        if self.strict_cbor {
            let re_encoded = decoded.encode();
            if re_encoded != enc {
                return Err(CtapError::InvalidResponse(
                    "Non-canonical CBOR from Authenticator".into(),
                ));
            }
        }

        Ok(decoded)
    }

    /// GET_INFO command.
    pub fn get_info(&mut self) -> Result<Info, CtapError> {
        let resp = self.send_cbor(ctap2_cmd::GET_INFO, None, &mut |_| {}, None)?;
        match resp {
            Value::Map(entries) => Ok(Info::from_cbor(&entries)),
            _ => Err(CtapError::InvalidResponse("Expected map".into())),
        }
    }

    /// clientPin command.
    #[allow(clippy::too_many_arguments)]
    pub fn client_pin(
        &mut self,
        pin_uv_protocol: u32,
        sub_cmd: u32,
        key_agreement: Option<Value>,
        pin_uv_param: Option<&[u8]>,
        new_pin_enc: Option<&[u8]>,
        pin_hash_enc: Option<&[u8]>,
        permissions: Option<u32>,
        permissions_rpid: Option<&str>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, CtapError> {
        let data = args_map(&[
            Some(Value::Int(pin_uv_protocol as i64)),
            Some(Value::Int(sub_cmd as i64)),
            key_agreement,
            pin_uv_param.map(|b| Value::Bytes(b.to_vec())),
            new_pin_enc.map(|b| Value::Bytes(b.to_vec())),
            pin_hash_enc.map(|b| Value::Bytes(b.to_vec())),
            None, // 7 unused
            None, // 8 unused
            permissions.map(|p| Value::Int(p as i64)),
            permissions_rpid.map(|s| Value::Text(s.to_string())),
        ]);
        self.send_cbor(ctap2_cmd::CLIENT_PIN, Some(&data), on_keepalive, cancel)
    }

    /// makeCredential command.
    #[allow(clippy::too_many_arguments)]
    pub fn make_credential(
        &mut self,
        client_data_hash: &[u8],
        rp: Value,
        user: Value,
        key_params: Value,
        exclude_list: Option<Value>,
        extensions: Option<Value>,
        options: Option<Value>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        enterprise_attestation: Option<u32>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<AttestationResponse, CtapError> {
        let data = args_map(&[
            Some(Value::Bytes(client_data_hash.to_vec())),
            Some(rp),
            Some(user),
            Some(key_params),
            exclude_list,
            extensions,
            options,
            pin_uv_param.map(|b| Value::Bytes(b.to_vec())),
            pin_uv_protocol.map(|p| Value::Int(p as i64)),
            enterprise_attestation.map(|e| Value::Int(e as i64)),
        ]);

        let resp = self.send_cbor(
            ctap2_cmd::MAKE_CREDENTIAL,
            Some(&data),
            on_keepalive,
            cancel,
        )?;
        match resp {
            Value::Map(entries) => AttestationResponse::from_cbor(&entries)
                .map_err(|e| CtapError::InvalidResponse(e.to_string())),
            _ => Err(CtapError::InvalidResponse("Expected map".into())),
        }
    }

    /// getAssertion command.
    #[allow(clippy::too_many_arguments)]
    pub fn get_assertion(
        &mut self,
        rp_id: &str,
        client_data_hash: &[u8],
        allow_list: Option<Value>,
        extensions: Option<Value>,
        options: Option<Value>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<AssertionResponse, CtapError> {
        let data = args_map(&[
            Some(Value::Text(rp_id.to_string())),
            Some(Value::Bytes(client_data_hash.to_vec())),
            allow_list,
            extensions,
            options,
            pin_uv_param.map(|b| Value::Bytes(b.to_vec())),
            pin_uv_protocol.map(|p| Value::Int(p as i64)),
        ]);

        let resp = self.send_cbor(ctap2_cmd::GET_ASSERTION, Some(&data), on_keepalive, cancel)?;
        match resp {
            Value::Map(entries) => AssertionResponse::from_cbor(&entries)
                .map_err(|e| CtapError::InvalidResponse(e.to_string())),
            _ => Err(CtapError::InvalidResponse("Expected map".into())),
        }
    }

    /// getNextAssertion command.
    pub fn get_next_assertion(&mut self) -> Result<AssertionResponse, CtapError> {
        let resp = self.send_cbor(ctap2_cmd::GET_NEXT_ASSERTION, None, &mut |_| {}, None)?;
        match resp {
            Value::Map(entries) => AssertionResponse::from_cbor(&entries)
                .map_err(|e| CtapError::InvalidResponse(e.to_string())),
            _ => Err(CtapError::InvalidResponse("Expected map".into())),
        }
    }

    /// Get all assertions (first + next).
    #[allow(clippy::too_many_arguments)]
    pub fn get_assertions(
        &mut self,
        rp_id: &str,
        client_data_hash: &[u8],
        allow_list: Option<Value>,
        extensions: Option<Value>,
        options: Option<Value>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<AssertionResponse>, CtapError> {
        let first = self.get_assertion(
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_param,
            pin_uv_protocol,
            on_keepalive,
            cancel,
        )?;

        let count = first.number_of_credentials.unwrap_or(1) as usize;
        let mut results = vec![first];
        for _ in 1..count {
            results.push(self.get_next_assertion()?);
        }
        Ok(results)
    }

    /// selection command.
    pub fn selection(
        &mut self,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<(), CtapError> {
        self.send_cbor(ctap2_cmd::SELECTION, None, on_keepalive, cancel)?;
        Ok(())
    }

    /// reset command.
    pub fn reset(
        &mut self,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<(), CtapError> {
        self.send_cbor(ctap2_cmd::RESET, None, on_keepalive, cancel)?;
        Ok(())
    }

    /// credentialMgmt command.
    ///
    /// Automatically determines the command byte from cached device info.
    pub fn credential_mgmt(
        &mut self,
        sub_cmd: Value,
        sub_cmd_params: Option<Value>,
        pin_uv_protocol: Option<Value>,
        pin_uv_param: Option<Value>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, CtapError> {
        let cmd_byte = if self.info.options.get("credMgmt") == Some(&true) {
            ctap2_cmd::CREDENTIAL_MGMT
        } else if self.info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && self.info.options.get("credentialMgmtPreview") == Some(&true)
        {
            ctap2_cmd::CREDENTIAL_MGMT_PRE
        } else {
            return Err(CtapError::InvalidResponse(
                "Authenticator does not support Credential Management".to_string(),
            ));
        };
        let data = args_map(&[Some(sub_cmd), sub_cmd_params, pin_uv_protocol, pin_uv_param]);
        self.send_cbor(cmd_byte, Some(&data), on_keepalive, cancel)
    }

    /// bioEnrollment command.
    ///
    /// Automatically determines the command byte from cached device info.
    #[allow(clippy::too_many_arguments)]
    pub fn bio_enrollment(
        &mut self,
        modality: Option<Value>,
        sub_cmd: Option<Value>,
        sub_cmd_params: Option<Value>,
        pin_uv_protocol: Option<Value>,
        pin_uv_param: Option<Value>,
        get_modality: Option<Value>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, CtapError> {
        let cmd_byte = if self.info.options.contains_key("bioEnroll") {
            ctap2_cmd::BIO_ENROLLMENT
        } else if self.info.versions.contains(&"FIDO_2_1_PRE".to_string())
            && self
                .info
                .options
                .contains_key("userVerificationMgmtPreview")
        {
            ctap2_cmd::BIO_ENROLLMENT_PRE
        } else {
            return Err(CtapError::InvalidResponse(
                "Authenticator does not support Bio Enroll".to_string(),
            ));
        };
        let data = args_map(&[
            modality,
            sub_cmd,
            sub_cmd_params,
            pin_uv_protocol,
            pin_uv_param,
            get_modality,
        ]);
        self.send_cbor(cmd_byte, Some(&data), on_keepalive, cancel)
    }

    /// largeBlobs command.
    #[allow(clippy::too_many_arguments)]
    pub fn large_blobs(
        &mut self,
        offset: u64,
        get: Option<u64>,
        set: Option<&[u8]>,
        length: Option<u64>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, CtapError> {
        let data = args_map(&[
            get.map(|g| Value::Int(g as i64)),
            set.map(|b| Value::Bytes(b.to_vec())),
            Some(Value::Int(offset as i64)),
            length.map(|l| Value::Int(l as i64)),
            pin_uv_param.map(|b| Value::Bytes(b.to_vec())),
            pin_uv_protocol.map(|p| Value::Int(p as i64)),
        ]);
        self.send_cbor(ctap2_cmd::LARGE_BLOBS, Some(&data), on_keepalive, cancel)
    }

    /// authenticatorConfig command.
    pub fn config(
        &mut self,
        sub_cmd: Value,
        sub_cmd_params: Option<Value>,
        pin_uv_protocol: Option<Value>,
        pin_uv_param: Option<Value>,
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Value, CtapError> {
        let data = args_map(&[Some(sub_cmd), sub_cmd_params, pin_uv_protocol, pin_uv_param]);
        self.send_cbor(ctap2_cmd::CONFIG, Some(&data), on_keepalive, cancel)
    }
}
