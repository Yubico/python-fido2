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

//! Data types for the W3C WebAuthn specification.
//!
//! Includes binary protocol types (`AuthenticatorData`, `AttestedCredentialData`,
//! `AttestationObject`, `CollectedClientData`), string enums, and JSON-serializable
//! request/response structures.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cbor;
use crate::cose::CoseKey;
use crate::utils::{sha256, websafe_decode, websafe_encode};

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("CBOR error: {0}")]
    Cbor(#[from] cbor::CborError),
    #[error("COSE error: {0}")]
    Cose(#[from] crate::cose::CoseError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// --- AAGUID ---

/// 16-byte Authenticator Attestation GUID.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Aaguid([u8; 16]);

impl Aaguid {
    pub const NONE: Aaguid = Aaguid([0u8; 16]);

    pub fn new(data: [u8; 16]) -> Self {
        Self(data)
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, WebauthnError> {
        let arr: [u8; 16] = data
            .try_into()
            .map_err(|_| WebauthnError::InvalidData("AAGUID must be 16 bytes".into()))?;
        Ok(Self(arr))
    }

    /// Parse from a UUID string (with or without dashes).
    pub fn parse(value: &str) -> Result<Self, WebauthnError> {
        let hex_str: String = value.chars().filter(|c| *c != '-').collect();
        let bytes = (0..hex_str.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex_str[i..i + 2], 16)
                    .map_err(|_| WebauthnError::InvalidData("Invalid AAGUID hex".into()))
            })
            .collect::<Result<Vec<u8>, _>>()?;
        Self::from_slice(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn is_none(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

impl fmt::Debug for Aaguid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AAGUID({})", self)
    }
}

impl fmt::Display for Aaguid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = crate::logging::hex_encode(&self.0);
        write!(
            f,
            "{}-{}-{}-{}-{}",
            &h[0..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..32]
        )
    }
}

// --- AuthenticatorData flags ---

bitflags::bitflags! {
    /// Authenticator data flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AuthenticatorDataFlags: u8 {
        /// User Present
        const UP = 0x01;
        /// User Verified
        const UV = 0x04;
        /// Backup Eligibility
        const BE = 0x08;
        /// Backup State
        const BS = 0x10;
        /// Attested credential data included
        const AT = 0x40;
        /// Extension data included
        const ED = 0x80;
    }
}

// --- AttestedCredentialData ---

/// Attested credential data embedded in AuthenticatorData.
#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    raw: Vec<u8>,
    pub aaguid: Aaguid,
    pub credential_id: Vec<u8>,
    pub public_key: CoseKey,
}

impl AttestedCredentialData {
    /// Parse from binary data, returning the parsed data and remaining bytes.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, &[u8]), WebauthnError> {
        if data.len() < 18 {
            return Err(WebauthnError::InvalidData(
                "AttestedCredentialData too short".into(),
            ));
        }

        let aaguid = Aaguid::from_slice(&data[..16])?;
        let cred_id_len = u16::from_be_bytes([data[16], data[17]]) as usize;

        let cred_start = 18;
        let cred_end = cred_start + cred_id_len;
        if data.len() < cred_end {
            return Err(WebauthnError::InvalidData(
                "Credential ID extends beyond data".into(),
            ));
        }
        let credential_id = data[cred_start..cred_end].to_vec();

        let (pub_key_cbor, rest) = cbor::decode_from(&data[cred_end..])?;
        let public_key = CoseKey::from_cbor(&pub_key_cbor)?;

        let consumed = data.len() - rest.len();
        let raw = data[..consumed].to_vec();

        Ok((
            Self {
                raw,
                aaguid,
                credential_id,
                public_key,
            },
            rest,
        ))
    }

    /// Create from components.
    pub fn create(aaguid: &Aaguid, credential_id: &[u8], public_key: &CoseKey) -> Self {
        let mut raw = Vec::new();
        raw.extend_from_slice(aaguid.as_bytes());
        raw.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        raw.extend_from_slice(credential_id);
        public_key.to_cbor().encode_to(&mut raw);

        Self {
            raw,
            aaguid: aaguid.clone(),
            credential_id: credential_id.to_vec(),
            public_key: public_key.clone(),
        }
    }

    /// Create from CTAP1 key handle and 65-byte public key.
    pub fn from_ctap1(key_handle: &[u8], public_key: &[u8]) -> Result<Self, WebauthnError> {
        let cose_key = CoseKey::from_ctap1(public_key)?;
        Ok(Self::create(&Aaguid::NONE, key_handle, &cose_key))
    }

    /// Get the raw binary representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

// --- AuthenticatorData ---

/// Binary authenticator data from a WebAuthn operation.
#[derive(Debug, Clone)]
pub struct AuthenticatorData {
    raw: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub flags: AuthenticatorDataFlags,
    pub counter: u32,
    pub credential_data: Option<AttestedCredentialData>,
    pub extensions: Option<cbor::Value>,
}

impl AuthenticatorData {
    /// Parse from binary data.
    pub fn from_bytes(data: &[u8]) -> Result<Self, WebauthnError> {
        if data.len() < 37 {
            return Err(WebauthnError::InvalidData(
                "AuthenticatorData too short".into(),
            ));
        }

        let rp_id_hash: [u8; 32] = data[..32].try_into().unwrap();
        let flags = AuthenticatorDataFlags::from_bits_retain(data[32]);
        let counter = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

        let mut rest = &data[37..];

        let credential_data = if flags.contains(AuthenticatorDataFlags::AT) {
            let (cred_data, r) = AttestedCredentialData::from_bytes(rest)?;
            rest = r;
            Some(cred_data)
        } else {
            None
        };

        let extensions = if flags.contains(AuthenticatorDataFlags::ED) {
            let (ext, r) = cbor::decode_from(rest)?;
            rest = r;
            Some(ext)
        } else {
            None
        };

        if !rest.is_empty() {
            return Err(WebauthnError::InvalidData(
                "Trailing data in AuthenticatorData".into(),
            ));
        }

        Ok(Self {
            raw: data.to_vec(),
            rp_id_hash,
            flags,
            counter,
            credential_data,
            extensions,
        })
    }

    /// Create from components.
    pub fn create(
        rp_id_hash: &[u8; 32],
        flags: AuthenticatorDataFlags,
        counter: u32,
        credential_data: Option<&AttestedCredentialData>,
        extensions: Option<&cbor::Value>,
    ) -> Self {
        let mut raw = Vec::new();
        raw.extend_from_slice(rp_id_hash);
        raw.push(flags.bits());
        raw.extend_from_slice(&counter.to_be_bytes());
        if let Some(cred) = credential_data {
            raw.extend_from_slice(cred.as_bytes());
        }
        if let Some(ext) = extensions {
            ext.encode_to(&mut raw);
        }

        Self {
            raw,
            rp_id_hash: *rp_id_hash,
            flags,
            counter,
            credential_data: credential_data.cloned(),
            extensions: extensions.cloned(),
        }
    }

    /// Get the raw binary representation.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn is_user_present(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::UP)
    }

    pub fn is_user_verified(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::UV)
    }

    pub fn is_backup_eligible(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::BE)
    }

    pub fn is_backed_up(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::BS)
    }

    pub fn is_attested(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::AT)
    }

    pub fn has_extension_data(&self) -> bool {
        self.flags.contains(AuthenticatorDataFlags::ED)
    }
}

// --- AttestationObject ---

/// CBOR-encoded attestation object.
#[derive(Debug, Clone)]
pub struct AttestationObject {
    raw: Vec<u8>,
    pub fmt: String,
    pub auth_data: AuthenticatorData,
    pub att_stmt: cbor::Value,
}

impl AttestationObject {
    /// Parse from CBOR-encoded bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, WebauthnError> {
        let value = cbor::decode(data)?;

        let fmt = value
            .map_get_text("fmt")
            .and_then(|v| v.as_text())
            .ok_or_else(|| WebauthnError::InvalidData("Missing fmt".into()))?
            .to_string();

        let auth_data_bytes = value
            .map_get_text("authData")
            .and_then(|v| v.as_bytes())
            .ok_or_else(|| WebauthnError::InvalidData("Missing authData".into()))?;

        let auth_data = AuthenticatorData::from_bytes(auth_data_bytes)?;

        let att_stmt = value
            .map_get_text("attStmt")
            .cloned()
            .unwrap_or(cbor::Value::Map(vec![]));

        Ok(Self {
            raw: data.to_vec(),
            fmt,
            auth_data,
            att_stmt,
        })
    }

    /// Create from components.
    pub fn create(
        fmt: &str,
        auth_data: &AuthenticatorData,
        att_stmt: &cbor::Value,
    ) -> Self {
        let cbor_val = cbor::Value::Map(vec![
            (
                cbor::Value::Text("fmt".into()),
                cbor::Value::Text(fmt.into()),
            ),
            (
                cbor::Value::Text("authData".into()),
                cbor::Value::Bytes(auth_data.as_bytes().to_vec()),
            ),
            (
                cbor::Value::Text("attStmt".into()),
                att_stmt.clone(),
            ),
        ]);
        let raw = cbor_val.encode();

        Self {
            raw,
            fmt: fmt.to_string(),
            auth_data: auth_data.clone(),
            att_stmt: att_stmt.clone(),
        }
    }

    /// Get the raw CBOR-encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

// --- CollectedClientData ---

/// JSON-encoded client data.
#[derive(Debug, Clone)]
pub struct CollectedClientData {
    raw: Vec<u8>,
    pub type_: String,
    pub challenge: Vec<u8>,
    pub origin: String,
    pub cross_origin: bool,
}

/// Well-known collected client data types.
pub mod client_data_type {
    pub const CREATE: &str = "webauthn.create";
    pub const GET: &str = "webauthn.get";
}

impl CollectedClientData {
    /// Parse from JSON-encoded bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, WebauthnError> {
        let json: serde_json::Value = serde_json::from_slice(data)?;

        let type_ = json["type"]
            .as_str()
            .ok_or_else(|| WebauthnError::InvalidData("Missing type".into()))?
            .to_string();

        let challenge_str = json["challenge"]
            .as_str()
            .ok_or_else(|| WebauthnError::InvalidData("Missing challenge".into()))?;
        let challenge = websafe_decode(challenge_str)
            .map_err(|_| WebauthnError::InvalidData("Invalid challenge encoding".into()))?;

        let origin = json["origin"]
            .as_str()
            .ok_or_else(|| WebauthnError::InvalidData("Missing origin".into()))?
            .to_string();

        let cross_origin = json
            .get("crossOrigin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Ok(Self {
            raw: data.to_vec(),
            type_,
            challenge,
            origin,
            cross_origin,
        })
    }

    /// Create from components.
    pub fn create(
        type_: &str,
        challenge: &[u8],
        origin: &str,
        cross_origin: bool,
    ) -> Self {
        let json = serde_json::json!({
            "type": type_,
            "challenge": websafe_encode(challenge),
            "origin": origin,
            "crossOrigin": cross_origin,
        });
        let raw = json.to_string().into_bytes();

        Self {
            raw,
            type_: type_.to_string(),
            challenge: challenge.to_vec(),
            origin: origin.to_string(),
            cross_origin,
        }
    }

    /// Get the raw JSON-encoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Base64url-encoded representation.
    pub fn b64(&self) -> String {
        websafe_encode(&self.raw)
    }

    /// SHA-256 hash of the raw client data.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.raw)
    }
}

// --- String enums ---

macro_rules! string_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident = $value:expr),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant,)*
            Unknown(String),
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)*
                    Self::Unknown(s) => s,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $($value => Self::$variant,)*
                    other => Self::Unknown(other.to_string()),
                }
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                Ok(Self::from(s.as_str()))
            }
        }
    };
}

string_enum! {
    /// Attestation conveyance preference.
    AttestationConveyancePreference {
        None_ = "none",
        Indirect = "indirect",
        Direct = "direct",
        Enterprise = "enterprise",
    }
}

string_enum! {
    /// User verification requirement.
    UserVerificationRequirement {
        Required = "required",
        Preferred = "preferred",
        Discouraged = "discouraged",
    }
}

string_enum! {
    /// Resident key requirement.
    ResidentKeyRequirement {
        Required = "required",
        Preferred = "preferred",
        Discouraged = "discouraged",
    }
}

string_enum! {
    /// Authenticator attachment modality.
    AuthenticatorAttachment {
        Platform = "platform",
        CrossPlatform = "cross-platform",
    }
}

string_enum! {
    /// Authenticator transport.
    AuthenticatorTransport {
        Usb = "usb",
        Nfc = "nfc",
        Ble = "ble",
        Hybrid = "hybrid",
        Internal = "internal",
    }
}

string_enum! {
    /// Public key credential type.
    PublicKeyCredentialType {
        PublicKey = "public-key",
    }
}

string_enum! {
    /// Public key credential hint.
    PublicKeyCredentialHint {
        SecurityKey = "security-key",
        ClientDevice = "client-device",
        Hybrid = "hybrid",
    }
}

// --- JSON data structures ---

/// Helper module for serializing bytes as base64url in JSON.
mod base64url_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::utils::{websafe_decode, websafe_encode};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&websafe_encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        websafe_decode(&s).map_err(serde::de::Error::custom)
    }
}

#[allow(dead_code)]
mod base64url_bytes_option {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::utils::{websafe_decode, websafe_encode};

    pub fn serialize<S: Serializer>(
        data: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match data {
            Some(bytes) => serializer.serialize_str(&websafe_encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => websafe_decode(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Relying party entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl PublicKeyCredentialRpEntity {
    /// SHA-256 hash of the RP ID, if set.
    pub fn id_hash(&self) -> Option<[u8; 32]> {
        self.id.as_ref().map(|id| sha256(id.as_bytes()))
    }
}

/// User entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(with = "base64url_bytes")]
    pub id: Vec<u8>,
    #[serde(
        rename = "displayName",
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
}

/// Public key credential algorithm parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub type_: PublicKeyCredentialType,
    pub alg: i64,
}

/// Credential descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: PublicKeyCredentialType,
    #[serde(with = "base64url_bytes")]
    pub id: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// Authenticator selection criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
}

/// Options for creating a public key credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    #[serde(with = "base64url_bytes")]
    pub challenge: Vec<u8>,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Options for getting a public key credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialRequestOptions {
    #[serde(with = "base64url_bytes")]
    pub challenge: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<PublicKeyCredentialHint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn test_aaguid() {
        let aaguid = Aaguid::NONE;
        assert!(aaguid.is_none());
        assert_eq!(
            aaguid.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );

        let parsed = Aaguid::parse("01020304-0506-0708-090a-0b0c0d0e0f10").unwrap();
        assert!(!parsed.is_none());
        assert_eq!(
            parsed.to_string(),
            "01020304-0506-0708-090a-0b0c0d0e0f10"
        );
    }

    #[test]
    fn test_authenticator_data_minimal() {
        // 32 bytes rp_id_hash + 1 byte flags + 4 bytes counter
        let rp_id_hash = sha256(b"example.com");
        let flags = AuthenticatorDataFlags::UP;
        let counter = 42u32;

        let auth_data = AuthenticatorData::create(&rp_id_hash, flags, counter, None, None);
        assert_eq!(auth_data.as_bytes().len(), 37);
        assert!(auth_data.is_user_present());
        assert!(!auth_data.is_user_verified());
        assert_eq!(auth_data.counter, 42);

        // Re-parse
        let parsed = AuthenticatorData::from_bytes(auth_data.as_bytes()).unwrap();
        assert_eq!(parsed.rp_id_hash, rp_id_hash);
        assert_eq!(parsed.counter, 42);
        assert!(parsed.is_user_present());
        assert!(parsed.credential_data.is_none());
        assert!(parsed.extensions.is_none());
    }

    #[test]
    fn test_authenticator_data_with_credential() {
        let rp_id_hash = sha256(b"example.com");
        let flags = AuthenticatorDataFlags::UP | AuthenticatorDataFlags::AT;

        let mut key_params = BTreeMap::new();
        key_params.insert(1, cbor::Value::Int(2));
        key_params.insert(3, cbor::Value::Int(-7));
        key_params.insert(-1, cbor::Value::Int(1));
        key_params.insert(-2, cbor::Value::Bytes(vec![0xAA; 32]));
        key_params.insert(-3, cbor::Value::Bytes(vec![0xBB; 32]));
        let cose_key = CoseKey::from_map(key_params);

        let cred_data =
            AttestedCredentialData::create(&Aaguid::NONE, b"credential-id", &cose_key);
        let auth_data =
            AuthenticatorData::create(&rp_id_hash, flags, 0, Some(&cred_data), None);

        let parsed = AuthenticatorData::from_bytes(auth_data.as_bytes()).unwrap();
        assert!(parsed.is_attested());
        let cred = parsed.credential_data.unwrap();
        assert!(cred.aaguid.is_none());
        assert_eq!(cred.credential_id, b"credential-id");
    }

    #[test]
    fn test_attestation_object_roundtrip() {
        let rp_id_hash = sha256(b"example.com");
        let flags = AuthenticatorDataFlags::UP;
        let auth_data = AuthenticatorData::create(&rp_id_hash, flags, 1, None, None);
        let att_stmt = cbor::Value::Map(vec![]);

        let att_obj = AttestationObject::create("none", &auth_data, &att_stmt);
        let parsed = AttestationObject::from_bytes(att_obj.as_bytes()).unwrap();

        assert_eq!(parsed.fmt, "none");
        assert_eq!(parsed.auth_data.counter, 1);
    }

    #[test]
    fn test_collected_client_data() {
        let cd = CollectedClientData::create(
            client_data_type::CREATE,
            b"challenge-bytes",
            "https://example.com",
            false,
        );

        assert_eq!(cd.type_, client_data_type::CREATE);
        assert_eq!(cd.challenge, b"challenge-bytes");
        assert_eq!(cd.origin, "https://example.com");
        assert!(!cd.cross_origin);

        let b64 = cd.b64();
        assert!(!b64.is_empty());

        let hash = cd.hash();
        assert_eq!(hash.len(), 32);

        // Re-parse
        let parsed = CollectedClientData::from_bytes(cd.as_bytes()).unwrap();
        assert_eq!(parsed.type_, cd.type_);
        assert_eq!(parsed.challenge, cd.challenge);
        assert_eq!(parsed.origin, cd.origin);
    }

    #[test]
    fn test_string_enums() {
        let att = AttestationConveyancePreference::from("direct");
        assert_eq!(att, AttestationConveyancePreference::Direct);
        assert_eq!(att.as_str(), "direct");

        let unknown = AttestationConveyancePreference::from("future-value");
        assert!(matches!(unknown, AttestationConveyancePreference::Unknown(_)));
        assert_eq!(unknown.as_str(), "future-value");
    }

    #[test]
    fn test_json_serialization() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };

        let json = serde_json::to_string(&rp).unwrap();
        assert!(json.contains("\"name\":\"Example\""));
        assert!(json.contains("\"id\":\"example.com\""));

        let parsed: PublicKeyCredentialRpEntity = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, rp);
    }

    #[test]
    fn test_credential_descriptor_base64url() {
        let desc = PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: vec![0x01, 0x02, 0x03],
            transports: Some(vec![AuthenticatorTransport::Usb]),
        };

        let json = serde_json::to_string(&desc).unwrap();
        // id should be base64url-encoded
        assert!(json.contains("\"id\":\"AQID\""));

        let parsed: PublicKeyCredentialDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_creation_options_json() {
        let options = PublicKeyCredentialCreationOptions {
            rp: PublicKeyCredentialRpEntity {
                name: "Example".into(),
                id: Some("example.com".into()),
            },
            user: PublicKeyCredentialUserEntity {
                name: Some("alice".into()),
                id: vec![1, 2, 3, 4],
                display_name: Some("Alice".into()),
            },
            challenge: vec![0xDE, 0xAD, 0xBE, 0xEF],
            pub_key_cred_params: vec![PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: -7,
            }],
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_selection: None,
            hints: None,
            attestation: None,
            attestation_formats: None,
            extensions: None,
        };

        let json = serde_json::to_string(&options).unwrap();
        let parsed: PublicKeyCredentialCreationOptions =
            serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.challenge, options.challenge);
        assert_eq!(parsed.rp.name, "Example");
    }
}
