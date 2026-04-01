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

//! CTAP2 extension processing for the FIDO2 client.
//!
//! Provides the extension trait system and implementations for standard
//! CTAP2/WebAuthn extensions: hmac-secret (prf), largeBlob, credBlob,
//! credProtect, minPinLength, and credProps.

use std::collections::BTreeMap;

use crate::blob::LargeBlobs;
use crate::ctap2::{AssertionResponse, AttestationResponse, Ctap2, Info};
use crate::pin::{ClientPin, CoseKeyAgreement, PinProtocol};
use fido2_server::cbor::Value;
use fido2_server::utils::sha256;

/// Authenticator extension inputs: maps extension name to CBOR value.
pub type ExtensionInputs = BTreeMap<String, Value>;

/// Client extension outputs: maps extension name to a JSON-like CBOR value.
pub type ExtensionOutputs = BTreeMap<String, Value>;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Processing state for a registration (makeCredential) extension.
pub trait RegistrationExtensionProcessor {
    /// Additional pinUvAuthToken permissions required by this extension.
    fn permissions(&self) -> u32 {
        0
    }

    /// Prepare authenticator extension inputs.
    fn prepare_inputs(&self, _pin_token: Option<&[u8]>) -> Option<ExtensionInputs> {
        None
    }

    /// Prepare client extension outputs from the attestation response.
    fn prepare_outputs(
        &self,
        _response: &AttestationResponse,
        _pin_token: Option<&[u8]>,
        _ctap: &Ctap2,
    ) -> Option<ExtensionOutputs> {
        None
    }
}

/// Processing state for an authentication (getAssertion) extension.
pub trait AuthenticationExtensionProcessor {
    /// Additional pinUvAuthToken permissions required by this extension.
    fn permissions(&self) -> u32 {
        0
    }

    /// Prepare authenticator extension inputs.
    fn prepare_inputs(
        &self,
        _selected: Option<&Value>,
        _pin_token: Option<&[u8]>,
    ) -> Option<ExtensionInputs> {
        None
    }

    /// Prepare client extension outputs from a single assertion response.
    fn prepare_outputs(
        &self,
        _response: &AssertionResponse,
        _pin_token: Option<&[u8]>,
        _ctap: &Ctap2,
    ) -> Option<ExtensionOutputs> {
        None
    }
}

/// Factory for extension processors. Reusable across multiple requests.
pub trait Ctap2Extension {
    /// Whether the authenticator supports this extension.
    fn is_supported(&self, info: &Info) -> bool;

    /// Create a registration processor, or None if extension not applicable.
    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>>;

    /// Create an authentication processor, or None if extension not applicable.
    fn get_assertion(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        allow_credentials: Option<&[Value]>,
        pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>>;
}

/// Return the default set of extensions.
pub fn default_extensions(allow_hmac_secret: bool) -> Vec<Box<dyn Ctap2Extension>> {
    vec![
        Box::new(HmacSecretExtension::new(allow_hmac_secret)),
        Box::new(LargeBlobExtension),
        Box::new(CredBlobExtension),
        Box::new(CredProtectExtension),
        Box::new(MinPinLengthExtension),
        Box::new(CredPropsExtension),
    ]
}

// ---------------------------------------------------------------------------
// Simple processor (static inputs/outputs)
// ---------------------------------------------------------------------------

struct SimpleRegistrationProcessor {
    inputs: Option<ExtensionInputs>,
    outputs: Option<ExtensionOutputs>,
}

impl RegistrationExtensionProcessor for SimpleRegistrationProcessor {
    fn prepare_inputs(&self, _pin_token: Option<&[u8]>) -> Option<ExtensionInputs> {
        self.inputs.clone()
    }

    fn prepare_outputs(
        &self,
        _response: &AttestationResponse,
        _pin_token: Option<&[u8]>,
        _ctap: &Ctap2,
    ) -> Option<ExtensionOutputs> {
        self.outputs.clone()
    }
}

struct SimpleAuthenticationProcessor {
    perms: u32,
    inputs: Option<ExtensionInputs>,
}

impl AuthenticationExtensionProcessor for SimpleAuthenticationProcessor {
    fn permissions(&self) -> u32 {
        self.perms
    }

    fn prepare_inputs(
        &self,
        _selected: Option<&Value>,
        _pin_token: Option<&[u8]>,
    ) -> Option<ExtensionInputs> {
        self.inputs.clone()
    }
}

// ---------------------------------------------------------------------------
// HmacSecretExtension (prf + hmac-secret)
// ---------------------------------------------------------------------------

const HMAC_SECRET_NAME: &str = "hmac-secret";
const HMAC_SECRET_MC_NAME: &str = "hmac-secret-mc";
const SALT_LEN: usize = 32;

fn prf_salt(secret: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(13 + secret.len());
    data.extend_from_slice(b"WebAuthn PRF\0");
    data.extend_from_slice(secret);
    sha256(&data)
}

/// Helper to extract salt bytes from a JSON value.
fn get_salt_bytes(v: &serde_json::Value) -> Option<Vec<u8>> {
    v.as_str()
        .and_then(|s| fido2_server::utils::websafe_decode(s).ok())
        .or_else(|| {
            // Also accept raw byte arrays if present
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_u64().map(|n| n as u8))
                    .collect()
            })
        })
}

/// Prepare salts from prf/hmac-secret extension inputs.
/// Returns (salt1, salt2) where salt2 may be empty.
fn prepare_salts(
    prf: Option<&serde_json::Value>,
    hmac: Option<&serde_json::Value>,
    allow_list: Option<&[Value]>,
    selected: Option<&Value>,
    is_prf: bool,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if is_prf {
        let prf = prf?;
        let mut secrets = prf.get("eval");

        // Handle evalByCredential
        if let Some(by_creds) = prf.get("evalByCredential")
            && let Some(by_creds_obj) = by_creds.as_object()
        {
            if allow_list.is_none() && !by_creds_obj.is_empty() {
                return None; // evalByCredentials requires allowCredentials
            }
            if let Some(selected_val) = selected {
                // Get the credential ID from selected and look up in evalByCredential
                if let Some(cred_id) = selected_val.map_get_text("id").and_then(|v| v.as_bytes()) {
                    let key = fido2_server::utils::websafe_encode(cred_id);
                    if let Some(per_cred) = by_creds_obj.get(&key) {
                        secrets = Some(per_cred);
                    }
                }
            }
        }

        let secrets = secrets?;
        let first = secrets.get("first").and_then(get_salt_bytes)?;
        let second = secrets
            .get("second")
            .and_then(get_salt_bytes)
            .unwrap_or_default();

        let salt1 = prf_salt(&first);
        let salt2 = if second.is_empty() {
            Vec::new()
        } else {
            prf_salt(&second).to_vec()
        };
        Some((salt1.to_vec(), salt2))
    } else {
        let hmac = hmac?;
        let salt1 = hmac.get("salt1").and_then(get_salt_bytes)?;
        let salt2 = hmac
            .get("salt2")
            .and_then(get_salt_bytes)
            .unwrap_or_default();

        if salt1.len() != SALT_LEN || (!salt2.is_empty() && salt2.len() != SALT_LEN) {
            return None;
        }
        Some((salt1, salt2))
    }
}

/// Format hmac-secret outputs as extension outputs.
fn format_hmac_outputs(
    enabled: Option<bool>,
    decrypted: Option<Vec<u8>>,
    is_prf: bool,
) -> Option<ExtensionOutputs> {
    let output1 = decrypted.as_ref().map(|d| &d[..SALT_LEN.min(d.len())]);
    let output2 = decrypted
        .as_ref()
        .filter(|d| d.len() > SALT_LEN)
        .map(|d| &d[SALT_LEN..]);

    let mut outputs = ExtensionOutputs::new();

    if is_prf {
        let mut result = Vec::new();
        if enabled == Some(true) {
            result.push((Value::Text("enabled".into()), Value::Bool(true)));
        }
        if let Some(o1) = output1 {
            let mut results_map = vec![(Value::Text("first".into()), Value::Bytes(o1.to_vec()))];
            if let Some(o2) = output2 {
                results_map.push((Value::Text("second".into()), Value::Bytes(o2.to_vec())));
            }
            result.push((Value::Text("results".into()), Value::Map(results_map)));
        }
        if !result.is_empty() {
            outputs.insert("prf".into(), Value::Map(result));
        }
    } else {
        if let Some(en) = enabled {
            outputs.insert("hmacCreateSecret".into(), Value::Bool(en));
        }
        if let Some(o1) = output1 {
            let mut secret_map = vec![(Value::Text("output1".into()), Value::Bytes(o1.to_vec()))];
            if let Some(o2) = output2 {
                secret_map.push((Value::Text("output2".into()), Value::Bytes(o2.to_vec())));
            }
            outputs.insert("hmacGetSecret".into(), Value::Map(secret_map));
        }
    }

    if outputs.is_empty() {
        None
    } else {
        Some(outputs)
    }
}

/// CTAP2 hmac-secret extension, supporting both prf and hmac-secret.
pub struct HmacSecretExtension {
    allow_hmac_secret: bool,
}

impl HmacSecretExtension {
    pub fn new(allow_hmac_secret: bool) -> Self {
        Self { allow_hmac_secret }
    }
}

impl Ctap2Extension for HmacSecretExtension {
    fn is_supported(&self, info: &Info) -> bool {
        info.extensions.iter().any(|e| e == HMAC_SECRET_NAME)
    }

    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        let ext = extensions?;
        let is_prf = ext.get("prf").is_some();
        let is_hmac = self.allow_hmac_secret
            && ext.get("hmacCreateSecret") == Some(&serde_json::Value::Bool(true));
        let pin_protocol = pin_protocol?;
        let info = ctap.info();

        if !self.is_supported(info) || (!is_prf && !is_hmac) {
            return None;
        }

        let mut inputs = ExtensionInputs::new();
        inputs.insert(HMAC_SECRET_NAME.into(), Value::Bool(true));

        let mut shared_secret = None;

        // Check for hmac-secret-mc (salts during registration)
        if info.extensions.iter().any(|e| e == HMAC_SECRET_MC_NAME) {
            let prf_input = ext.get("prf");
            let hmac_input = if is_hmac {
                ext.get("hmacGetSecret")
            } else {
                None
            };

            if let Some(salts) = prepare_salts(prf_input, hmac_input, None, None, is_prf) {
                let client_pin = ClientPin::new(ctap, Some(pin_protocol)).ok()?;
                let (key_agreement, ss) = client_pin._get_shared_secret().ok()?;

                let mut salt_data = salts.0;
                salt_data.extend_from_slice(&salts.1);
                let salt_enc = pin_protocol.encrypt(&ss, &salt_data).ok()?;
                let salt_auth = pin_protocol.authenticate(&ss, &salt_enc);

                inputs.insert(
                    HMAC_SECRET_MC_NAME.into(),
                    Value::Map(vec![
                        (Value::Int(1), key_agreement.to_value()),
                        (Value::Int(2), Value::Bytes(salt_enc)),
                        (Value::Int(3), Value::Bytes(salt_auth)),
                        (Value::Int(4), Value::Int(pin_protocol.version() as i64)),
                    ]),
                );

                shared_secret = Some(ss);
            }
        }

        struct Processor {
            inputs: ExtensionInputs,
            shared_secret: Option<Vec<u8>>,
            pin_protocol: PinProtocol,
            is_prf: bool,
        }

        impl RegistrationExtensionProcessor for Processor {
            fn prepare_inputs(&self, _pin_token: Option<&[u8]>) -> Option<ExtensionInputs> {
                Some(self.inputs.clone())
            }

            fn prepare_outputs(
                &self,
                response: &AttestationResponse,
                _pin_token: Option<&[u8]>,
                _ctap: &Ctap2,
            ) -> Option<ExtensionOutputs> {
                let extensions = &response.auth_data.extensions;
                let enabled = extensions
                    .as_ref()
                    .and_then(|e| e.map_get_text(HMAC_SECRET_NAME))
                    .and_then(|v| v.as_bool());
                let mc_value = extensions
                    .as_ref()
                    .and_then(|e| e.map_get_text(HMAC_SECRET_MC_NAME))
                    .and_then(|v| v.as_bytes());
                let decrypted = match (mc_value, &self.shared_secret) {
                    (Some(value), Some(ss)) => self.pin_protocol.decrypt(ss, value).ok(),
                    _ => None,
                };
                format_hmac_outputs(enabled, decrypted, self.is_prf)
            }
        }

        Some(Box::new(Processor {
            inputs,
            shared_secret,
            pin_protocol,
            is_prf,
        }))
    }

    fn get_assertion(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        allow_credentials: Option<&[Value]>,
        pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        let ext = extensions?;
        let prf_input = ext.get("prf");
        let hmac_input = if self.allow_hmac_secret {
            ext.get("hmacGetSecret")
        } else {
            None
        };
        let is_prf = prf_input.is_some();
        let pin_protocol = pin_protocol?;

        if !self.is_supported(ctap.info()) || (!is_prf && hmac_input.is_none()) {
            return None;
        }

        // Perform ECDH key agreement now; processor owns the result
        let client_pin = ClientPin::new(ctap, Some(pin_protocol)).ok()?;
        let (key_agreement, shared_secret) = client_pin._get_shared_secret().ok()?;

        struct Processor {
            key_agreement: CoseKeyAgreement,
            shared_secret: Vec<u8>,
            pin_protocol: PinProtocol,
            is_prf: bool,
            prf_input: Option<serde_json::Value>,
            hmac_input: Option<serde_json::Value>,
            allow_credentials: Option<Vec<Value>>,
        }

        impl AuthenticationExtensionProcessor for Processor {
            fn prepare_inputs(
                &self,
                selected: Option<&Value>,
                _pin_token: Option<&[u8]>,
            ) -> Option<ExtensionInputs> {
                let salts = prepare_salts(
                    self.prf_input.as_ref(),
                    self.hmac_input.as_ref(),
                    self.allow_credentials.as_deref(),
                    selected,
                    self.is_prf,
                )?;

                let mut salt_data = salts.0;
                salt_data.extend_from_slice(&salts.1);
                let salt_enc = self
                    .pin_protocol
                    .encrypt(&self.shared_secret, &salt_data)
                    .ok()?;
                let salt_auth = self
                    .pin_protocol
                    .authenticate(&self.shared_secret, &salt_enc);

                let mut inputs = ExtensionInputs::new();
                inputs.insert(
                    HMAC_SECRET_NAME.into(),
                    Value::Map(vec![
                        (Value::Int(1), self.key_agreement.to_value()),
                        (Value::Int(2), Value::Bytes(salt_enc)),
                        (Value::Int(3), Value::Bytes(salt_auth)),
                        (
                            Value::Int(4),
                            Value::Int(self.pin_protocol.version() as i64),
                        ),
                    ]),
                );
                Some(inputs)
            }

            fn prepare_outputs(
                &self,
                response: &AssertionResponse,
                _pin_token: Option<&[u8]>,
                _ctap: &Ctap2,
            ) -> Option<ExtensionOutputs> {
                let extensions = &response.auth_data.extensions;
                let value = extensions
                    .as_ref()
                    .and_then(|e| e.map_get_text(HMAC_SECRET_NAME))
                    .and_then(|v| v.as_bytes())?;
                let decrypted = self.pin_protocol.decrypt(&self.shared_secret, value).ok()?;
                format_hmac_outputs(None, Some(decrypted), self.is_prf)
            }
        }

        Some(Box::new(Processor {
            key_agreement,
            shared_secret,
            pin_protocol,
            is_prf,
            prf_input: prf_input.cloned(),
            hmac_input: hmac_input.cloned(),
            allow_credentials: allow_credentials.map(|c| c.to_vec()),
        }))
    }
}

// ---------------------------------------------------------------------------
// LargeBlobExtension
// ---------------------------------------------------------------------------

const LARGE_BLOB_KEY_NAME: &str = "largeBlobKey";

pub struct LargeBlobExtension;

impl Ctap2Extension for LargeBlobExtension {
    fn is_supported(&self, info: &Info) -> bool {
        info.extensions.iter().any(|e| e == LARGE_BLOB_KEY_NAME)
            && info.options.get("largeBlobs") == Some(&true)
    }

    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        let ext = extensions?;
        let lb = ext.get("largeBlob")?;

        // Validate: no read/write during registration
        if lb.get("read").is_some() || lb.get("write").is_some() {
            return None; // Invalid parameters
        }

        let support = lb.get("support").and_then(|v| v.as_str())?;
        if support == "required" && !self.is_supported(ctap.info()) {
            return None; // Required but not supported
        }

        struct Processor;

        impl RegistrationExtensionProcessor for Processor {
            fn prepare_inputs(&self, _pin_token: Option<&[u8]>) -> Option<ExtensionInputs> {
                let mut inputs = ExtensionInputs::new();
                inputs.insert(LARGE_BLOB_KEY_NAME.into(), Value::Bool(true));
                Some(inputs)
            }

            fn prepare_outputs(
                &self,
                response: &AttestationResponse,
                _pin_token: Option<&[u8]>,
                _ctap: &Ctap2,
            ) -> Option<ExtensionOutputs> {
                let supported = response.large_blob_key.is_some();
                let mut outputs = ExtensionOutputs::new();
                outputs.insert(
                    "largeBlob".into(),
                    Value::Map(vec![(
                        Value::Text("supported".into()),
                        Value::Bool(supported),
                    )]),
                );
                Some(outputs)
            }
        }

        Some(Box::new(Processor))
    }

    fn get_assertion(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _allow_credentials: Option<&[Value]>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        let ext = extensions?;
        let lb = ext.get("largeBlob")?;

        // Validate: no support during authentication, can't have both read and write
        if lb.get("support").is_some() {
            return None;
        }
        let read = lb.get("read").and_then(|v| v.as_bool()).unwrap_or(false);
        let write_data = lb.get("write").and_then(get_salt_bytes);
        if read && write_data.is_some() {
            return None;
        }

        if !self.is_supported(ctap.info()) {
            return None;
        }

        let perms = if write_data.is_some() {
            0x10 // LARGE_BLOB_WRITE
        } else {
            0
        };

        struct Processor {
            read: bool,
            write_data: Option<Vec<u8>>,
            perms: u32,
        }

        impl AuthenticationExtensionProcessor for Processor {
            fn permissions(&self) -> u32 {
                self.perms
            }

            fn prepare_inputs(
                &self,
                _selected: Option<&Value>,
                _pin_token: Option<&[u8]>,
            ) -> Option<ExtensionInputs> {
                let mut inputs = ExtensionInputs::new();
                inputs.insert(LARGE_BLOB_KEY_NAME.into(), Value::Bool(true));
                Some(inputs)
            }

            fn prepare_outputs(
                &self,
                response: &AssertionResponse,
                pin_token: Option<&[u8]>,
                ctap: &Ctap2,
            ) -> Option<ExtensionOutputs> {
                let blob_key = response.large_blob_key.as_ref()?;
                let mut outputs = ExtensionOutputs::new();

                if self.read {
                    let large_blobs = LargeBlobs::new(ctap, None, None).ok()?;
                    let blob = large_blobs.get_blob(blob_key).ok()?;
                    outputs.insert(
                        "largeBlob".into(),
                        Value::Map(vec![(Value::Text("blob".into()), Value::Bytes(blob?))]),
                    );
                } else if let Some(ref data) = self.write_data {
                    // Need pin_token for writing
                    let protocol = if pin_token.is_some() {
                        // Determine protocol from info
                        let info = ctap.info();
                        if info.pin_uv_protocols.contains(&2) {
                            Some(PinProtocol::V2)
                        } else if info.pin_uv_protocols.contains(&1) {
                            Some(PinProtocol::V1)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let large_blobs = LargeBlobs::new(ctap, protocol.as_ref(), pin_token).ok()?;
                    large_blobs.put_blob(blob_key, Some(data)).ok()?;
                    outputs.insert(
                        "largeBlob".into(),
                        Value::Map(vec![(Value::Text("written".into()), Value::Bool(true))]),
                    );
                }

                if outputs.is_empty() {
                    None
                } else {
                    Some(outputs)
                }
            }
        }

        Some(Box::new(Processor {
            read,
            write_data,
            perms,
        }))
    }
}

// ---------------------------------------------------------------------------
// CredBlobExtension
// ---------------------------------------------------------------------------

pub struct CredBlobExtension;

impl Ctap2Extension for CredBlobExtension {
    fn is_supported(&self, info: &Info) -> bool {
        info.extensions.iter().any(|e| e == "credBlob")
    }

    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        let ext = extensions?;
        if !self.is_supported(ctap.info()) {
            return None;
        }
        let blob = ext.get("credBlob").and_then(get_salt_bytes)?;
        let max_len = ctap.info().max_cred_blob_length;
        if max_len == 0 || blob.len() > max_len {
            return None;
        }

        let mut inputs = ExtensionInputs::new();
        inputs.insert("credBlob".into(), Value::Bytes(blob));
        Some(Box::new(SimpleRegistrationProcessor {
            inputs: Some(inputs),
            outputs: None,
        }))
    }

    fn get_assertion(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _allow_credentials: Option<&[Value]>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        let ext = extensions?;
        if !self.is_supported(ctap.info()) {
            return None;
        }
        if ext.get("getCredBlob") != Some(&serde_json::Value::Bool(true)) {
            return None;
        }

        let mut inputs = ExtensionInputs::new();
        inputs.insert("credBlob".into(), Value::Bool(true));
        Some(Box::new(SimpleAuthenticationProcessor {
            perms: 0,
            inputs: Some(inputs),
        }))
    }
}

// ---------------------------------------------------------------------------
// CredProtectExtension
// ---------------------------------------------------------------------------

pub struct CredProtectExtension;

impl CredProtectExtension {
    fn policy_to_int(policy: &str) -> Option<i64> {
        match policy {
            "userVerificationOptional" => Some(1),
            "userVerificationOptionalWithCredentialIDList" => Some(2),
            "userVerificationRequired" => Some(3),
            _ => None,
        }
    }
}

impl Ctap2Extension for CredProtectExtension {
    fn is_supported(&self, info: &Info) -> bool {
        info.extensions.iter().any(|e| e == "credProtect")
    }

    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        let ext = extensions?;
        let policy_str = ext
            .get("credentialProtectionPolicy")
            .and_then(|v| v.as_str())?;
        let index = Self::policy_to_int(policy_str)?;
        let enforce = ext
            .get("enforceCredentialProtectionPolicy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if enforce && !self.is_supported(ctap.info()) && index > 1 {
            return None; // Authenticator doesn't support credProtect
        }

        let mut inputs = ExtensionInputs::new();
        inputs.insert("credProtect".into(), Value::Int(index));
        Some(Box::new(SimpleRegistrationProcessor {
            inputs: Some(inputs),
            outputs: None,
        }))
    }

    fn get_assertion(
        &self,
        _ctap: &Ctap2,
        _extensions: Option<&serde_json::Value>,
        _allow_credentials: Option<&[Value]>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        None
    }
}

// ---------------------------------------------------------------------------
// MinPinLengthExtension
// ---------------------------------------------------------------------------

pub struct MinPinLengthExtension;

impl Ctap2Extension for MinPinLengthExtension {
    fn is_supported(&self, info: &Info) -> bool {
        info.options.get("setMinPINLength") == Some(&true)
    }

    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        let ext = extensions?;
        if !self.is_supported(ctap.info()) {
            return None;
        }
        if ext.get("minPinLength") != Some(&serde_json::Value::Bool(true)) {
            return None;
        }

        let mut inputs = ExtensionInputs::new();
        inputs.insert("minPinLength".into(), Value::Bool(true));
        Some(Box::new(SimpleRegistrationProcessor {
            inputs: Some(inputs),
            outputs: None,
        }))
    }

    fn get_assertion(
        &self,
        _ctap: &Ctap2,
        _extensions: Option<&serde_json::Value>,
        _allow_credentials: Option<&[Value]>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        None
    }
}

// ---------------------------------------------------------------------------
// CredPropsExtension
// ---------------------------------------------------------------------------

pub struct CredPropsExtension;

impl Ctap2Extension for CredPropsExtension {
    fn is_supported(&self, _info: &Info) -> bool {
        true // Always supported
    }

    fn make_credential(
        &self,
        ctap: &Ctap2,
        extensions: Option<&serde_json::Value>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        let ext = extensions?;
        if ext.get("credProps") != Some(&serde_json::Value::Bool(true)) {
            return None;
        }

        // Calculate rk value based on authenticator capabilities and request
        let info = ctap.info();
        let can_rk = info.options.get("rk") == Some(&true);

        // We need the authenticator_selection from the create options, but we don't
        // have it here. The rk value will be set by the client based on the options.
        // For now, just mark it as supported.
        let rk = can_rk; // Best guess without the full options context

        let mut outputs = ExtensionOutputs::new();
        outputs.insert(
            "credProps".into(),
            Value::Map(vec![(Value::Text("rk".into()), Value::Bool(rk))]),
        );

        Some(Box::new(SimpleRegistrationProcessor {
            inputs: None,
            outputs: Some(outputs),
        }))
    }

    fn get_assertion(
        &self,
        _ctap: &Ctap2,
        _extensions: Option<&serde_json::Value>,
        _allow_credentials: Option<&[Value]>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        None
    }
}
