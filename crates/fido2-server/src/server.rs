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

//! FIDO2 server implementation.
//!
//! Provides [`Fido2Server`] for WebAuthn relying party operations, as well as
//! RP ID validation against origins using the Public Suffix List.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::cose::{Algorithm, CoseKey};
use crate::utils::{bytes_eq, sha256, websafe_encode};
use crate::webauthn::{
    AttestationConveyancePreference, AttestationObject, AuthenticatorAttachment, AuthenticatorData,
    AuthenticatorDataFlags, AuthenticatorSelectionCriteria, CollectedClientData,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, ResidentKeyRequirement,
    UserVerificationRequirement,
};

// --- Error type ---

/// Errors returned by server operations.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("{0}")]
    Verification(String),
    #[error("{0}")]
    Configuration(String),
    #[error("WebAuthn error: {0}")]
    Webauthn(#[from] crate::webauthn::WebauthnError),
    #[error("COSE error: {0}")]
    Cose(#[from] crate::cose::CoseError),
}

// --- Public Suffix List ---

static PSL_DATA: &str = include_str!("../../../fido2/public_suffix_list.dat");

struct PslSets {
    suffixes: HashSet<String>,
    wildcards: HashSet<String>,
    exceptions: HashSet<String>,
}

static PSL: LazyLock<PslSets> = LazyLock::new(|| {
    let mut suffixes = HashSet::new();
    let mut wildcards = HashSet::new();
    let mut exceptions = HashSet::new();

    for line in PSL_DATA.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with("//") {
            continue;
        }
        if let Some(rest) = entry.strip_prefix('!') {
            exceptions.insert(rest.to_string());
        } else if let Some(rest) = entry.strip_prefix("*.") {
            wildcards.insert(rest.to_string());
        } else {
            suffixes.insert(entry.to_string());
        }
    }

    PslSets {
        suffixes,
        wildcards,
        exceptions,
    }
});

/// Check if a domain is a public suffix per the PSL algorithm.
///
/// See <https://github.com/publicsuffix/list/wiki/Format>.
fn is_public_suffix(domain: &str) -> bool {
    let psl = &*PSL;

    if psl.exceptions.contains(domain) {
        return false;
    }
    if psl.suffixes.contains(domain) {
        return true;
    }
    if let Some((_label, parent)) = domain.split_once('.')
        && psl.wildcards.contains(parent)
    {
        return true;
    }
    false
}

// --- RP ID verification ---

/// Checks if a WebAuthn RP ID is usable for a given origin.
///
/// The origin must use `https`, except for `http://localhost` and
/// `http://*.localhost` which are treated as secure contexts by most browsers.
pub fn verify_rp_id(rp_id: &str, origin: &str) -> bool {
    if rp_id.is_empty() {
        return false;
    }

    let parsed = match url::Url::parse(origin) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let scheme = parsed.scheme();
    let host = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };

    // WebAuthn requires a secure context (https).
    // Browsers also treat http://localhost and http://*.localhost as secure.
    if scheme != "https"
        && (scheme, host) != ("http", "localhost")
        && !(scheme == "http" && host.ends_with(".localhost"))
    {
        return false;
    }

    if host == rp_id {
        return true;
    }

    if host.ends_with(&format!(".{rp_id}")) && !is_public_suffix(rp_id) {
        return true;
    }

    false
}

// --- Registration/Authentication verification ---

/// Verify a registration (webauthn.create) response.
pub fn verify_registration(
    client_data: &CollectedClientData,
    attestation_object: &AttestationObject,
    challenge: &[u8],
    rp_id_hash: &[u8],
    user_verification_required: bool,
) -> Result<(), ServerError> {
    if client_data.type_ != "webauthn.create" {
        return Err(ServerError::Verification(
            "Incorrect type in CollectedClientData.".into(),
        ));
    }

    if !bytes_eq(&client_data.challenge, challenge) {
        return Err(ServerError::Verification(
            "Wrong challenge in response.".into(),
        ));
    }

    if !bytes_eq(&attestation_object.auth_data.rp_id_hash, rp_id_hash) {
        return Err(ServerError::Verification(
            "Wrong RP ID hash in response.".into(),
        ));
    }

    let flags = attestation_object.auth_data.flags;

    if !flags.contains(AuthenticatorDataFlags::UP) {
        return Err(ServerError::Verification(
            "User Present flag not set.".into(),
        ));
    }

    if user_verification_required && !flags.contains(AuthenticatorDataFlags::UV) {
        return Err(ServerError::Verification(
            "User verification required, but User Verified flag not set.".into(),
        ));
    }

    Ok(())
}

/// Verify an authentication (webauthn.get) response.
pub fn verify_authentication(
    client_data: &CollectedClientData,
    auth_data: &AuthenticatorData,
    challenge: &[u8],
    rp_id_hash: &[u8],
    user_verification_required: bool,
) -> Result<(), ServerError> {
    if client_data.type_ != "webauthn.get" {
        return Err(ServerError::Verification(
            "Incorrect type in CollectedClientData.".into(),
        ));
    }

    if !bytes_eq(&client_data.challenge, challenge) {
        return Err(ServerError::Verification(
            "Wrong challenge in response.".into(),
        ));
    }

    if !bytes_eq(&auth_data.rp_id_hash, rp_id_hash) {
        return Err(ServerError::Verification(
            "Wrong RP ID hash in response.".into(),
        ));
    }

    let flags = auth_data.flags;

    if !flags.contains(AuthenticatorDataFlags::UP) {
        return Err(ServerError::Verification(
            "User Present flag not set.".into(),
        ));
    }

    if user_verification_required && !flags.contains(AuthenticatorDataFlags::UV) {
        return Err(ServerError::Verification(
            "User verification required, but user verified flag not set.".into(),
        ));
    }

    Ok(())
}

// --- Internal state ---

/// Opaque state created by `register_begin` / `authenticate_begin` and
/// consumed by the corresponding `*_complete` method.
#[derive(Debug, Clone)]
pub struct ServerState {
    pub challenge: Vec<u8>,
    pub user_verification: Option<UserVerificationRequirement>,
}

impl ServerState {
    fn user_verification_required(&self) -> bool {
        self.user_verification
            .as_ref()
            .map(|uv| *uv == UserVerificationRequirement::Required)
            .unwrap_or(false)
    }
}

// --- Challenge helper ---

pub fn generate_or_validate_challenge(challenge: Option<&[u8]>) -> Result<Vec<u8>, ServerError> {
    match challenge {
        Some(c) => {
            if c.len() < 16 {
                return Err(ServerError::Configuration(
                    "Custom challenge length must be >= 16.".into(),
                ));
            }
            Ok(c.to_vec())
        }
        None => {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf)
                .map_err(|e| ServerError::Configuration(format!("RNG error: {e}")))?;
            Ok(buf.to_vec())
        }
    }
}

// --- Fido2Server ---

/// FIDO2 relying party server.
///
/// Handles the creation and verification of WebAuthn registration and
/// authentication ceremonies.
pub struct Fido2Server {
    pub rp: PublicKeyCredentialRpEntity,
    pub attestation: Option<AttestationConveyancePreference>,
    pub timeout: Option<u64>,
    pub allowed_algorithms: Vec<PublicKeyCredentialParameters>,
    rp_id_hash: [u8; 32],
}

impl Fido2Server {
    /// Create a new FIDO2 server for the given relying party.
    ///
    /// The RP entity must have an `id` set.
    pub fn new(
        rp: PublicKeyCredentialRpEntity,
        attestation: Option<AttestationConveyancePreference>,
    ) -> Result<Self, ServerError> {
        let rp_id = rp
            .id
            .as_deref()
            .ok_or_else(|| ServerError::Configuration("RP ID must be set.".into()))?;
        let rp_id_hash = sha256(rp_id.as_bytes());

        let allowed_algorithms = Algorithm::supported()
            .iter()
            .map(|alg| PublicKeyCredentialParameters {
                type_: PublicKeyCredentialType::PublicKey,
                alg: *alg as i64,
            })
            .collect();

        Ok(Self {
            rp,
            attestation,
            timeout: None,
            allowed_algorithms,
            rp_id_hash,
        })
    }

    /// SHA-256 hash of the RP ID.
    pub fn rp_id_hash(&self) -> &[u8; 32] {
        &self.rp_id_hash
    }

    /// RP ID string.
    pub fn rp_id(&self) -> &str {
        // Safe: we validated this in `new`.
        self.rp.id.as_deref().unwrap()
    }

    /// Verify that an origin is valid for this server's RP ID.
    pub fn verify_origin(&self, origin: &str) -> bool {
        verify_rp_id(self.rp_id(), origin)
    }

    /// Begin a registration ceremony.
    ///
    /// Returns the options to send to the client and the server state to
    /// pass to [`register_complete`](Self::register_complete).
    #[allow(clippy::too_many_arguments)]
    pub fn register_begin(
        &self,
        user: PublicKeyCredentialUserEntity,
        exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
        resident_key: Option<ResidentKeyRequirement>,
        user_verification: Option<UserVerificationRequirement>,
        authenticator_attachment: Option<AuthenticatorAttachment>,
        challenge: Option<&[u8]>,
        extensions: Option<serde_json::Value>,
    ) -> Result<(PublicKeyCredentialCreationOptions, ServerState), ServerError> {
        if self.allowed_algorithms.is_empty() {
            return Err(ServerError::Configuration(
                "Server has no allowed algorithms.".into(),
            ));
        }

        let challenge = generate_or_validate_challenge(challenge)?;
        let state = ServerState {
            challenge: challenge.clone(),
            user_verification: user_verification.clone(),
        };

        let authenticator_selection = if authenticator_attachment.is_some()
            || resident_key.is_some()
            || user_verification.is_some()
        {
            Some(AuthenticatorSelectionCriteria {
                authenticator_attachment,
                resident_key,
                user_verification: user_verification.clone(),
                require_resident_key: None,
            })
        } else {
            None
        };

        let options = PublicKeyCredentialCreationOptions {
            rp: self.rp.clone(),
            user,
            challenge,
            pub_key_cred_params: self.allowed_algorithms.clone(),
            timeout: self.timeout,
            exclude_credentials,
            authenticator_selection,
            hints: None,
            attestation: self.attestation.clone(),
            attestation_formats: None,
            extensions,
        };

        Ok((options, state))
    }

    /// Complete a registration ceremony.
    ///
    /// Verifies the client data and attestation object against the server
    /// state. Returns the authenticator data on success.
    ///
    /// Note: This does NOT verify the attestation statement itself. If
    /// attestation verification is required, the caller must verify
    /// `attestation_object.att_stmt` separately (e.g., via the attestation
    /// module).
    pub fn register_complete<'a>(
        &self,
        state: &ServerState,
        client_data: &CollectedClientData,
        attestation_object: &'a AttestationObject,
    ) -> Result<&'a AuthenticatorData, ServerError> {
        if !self.verify_origin(&client_data.origin) {
            return Err(ServerError::Verification(
                "Invalid origin in CollectedClientData.".into(),
            ));
        }

        verify_registration(
            client_data,
            attestation_object,
            &state.challenge,
            &self.rp_id_hash,
            state.user_verification_required(),
        )?;

        Ok(&attestation_object.auth_data)
    }

    /// Begin an authentication ceremony.
    ///
    /// Returns the options to send to the client and the server state to
    /// pass to [`authenticate_complete`](Self::authenticate_complete).
    pub fn authenticate_begin(
        &self,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
        user_verification: Option<UserVerificationRequirement>,
        challenge: Option<&[u8]>,
        extensions: Option<serde_json::Value>,
    ) -> Result<(PublicKeyCredentialRequestOptions, ServerState), ServerError> {
        let challenge = generate_or_validate_challenge(challenge)?;
        let state = ServerState {
            challenge: challenge.clone(),
            user_verification: user_verification.clone(),
        };

        let options = PublicKeyCredentialRequestOptions {
            challenge,
            timeout: self.timeout,
            rp_id: self.rp.id.clone(),
            allow_credentials,
            user_verification,
            hints: None,
            extensions,
        };

        Ok((options, state))
    }

    /// Complete an authentication ceremony.
    ///
    /// Verifies the client data, authenticator data, and signature against the
    /// server state and provided credentials. Returns the index (into the
    /// `credentials` slice) of the credential that was authenticated.
    pub fn authenticate_complete(
        &self,
        state: &ServerState,
        credentials: &[(Vec<u8>, CoseKey)],
        credential_id: &[u8],
        client_data: &CollectedClientData,
        auth_data: &AuthenticatorData,
        signature: &[u8],
    ) -> Result<usize, ServerError> {
        if !self.verify_origin(&client_data.origin) {
            return Err(ServerError::Verification(
                "Invalid origin in CollectedClientData.".into(),
            ));
        }

        verify_authentication(
            client_data,
            auth_data,
            &state.challenge,
            &self.rp_id_hash,
            state.user_verification_required(),
        )?;

        for (i, (cred_id, public_key)) in credentials.iter().enumerate() {
            if cred_id == credential_id {
                let mut signed_data = auth_data.as_bytes().to_vec();
                signed_data.extend_from_slice(&client_data.hash());
                public_key
                    .verify(&signed_data, signature)
                    .map_err(|_| ServerError::Verification("Invalid signature.".into()))?;
                return Ok(i);
            }
        }

        Err(ServerError::Verification("Unknown credential ID.".into()))
    }

    /// Encode a challenge as websafe base64 for serialization into state.
    pub fn encode_challenge(challenge: &[u8]) -> String {
        websafe_encode(challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_rp_id_exact_match() {
        assert!(verify_rp_id("example.com", "https://example.com"));
    }

    #[test]
    fn test_verify_rp_id_subdomain() {
        assert!(verify_rp_id("example.com", "https://www.example.com"));
        assert!(verify_rp_id("example.com", "https://sub.example.com"));
    }

    #[test]
    fn test_verify_rp_id_rejects_public_suffix() {
        assert!(!verify_rp_id("com", "https://example.com"));
        assert!(!verify_rp_id("co.uk", "https://example.co.uk"));
    }

    #[test]
    fn test_verify_rp_id_empty() {
        assert!(!verify_rp_id("", "https://example.com"));
    }

    #[test]
    fn test_verify_rp_id_http_rejected() {
        assert!(!verify_rp_id("example.com", "http://example.com"));
    }

    #[test]
    fn test_verify_rp_id_localhost_http() {
        assert!(verify_rp_id("localhost", "http://localhost"));
        assert!(verify_rp_id("localhost", "http://localhost:8080"));
        assert!(verify_rp_id("sub.localhost", "http://sub.localhost"));
    }

    #[test]
    fn test_verify_rp_id_no_match() {
        assert!(!verify_rp_id("other.com", "https://example.com"));
    }

    #[test]
    fn test_is_public_suffix_basic() {
        assert!(is_public_suffix("com"));
        assert!(is_public_suffix("org"));
        assert!(!is_public_suffix("example.com"));
    }

    #[test]
    fn test_is_public_suffix_wildcard() {
        assert!(is_public_suffix("foo.ck"));
    }

    #[test]
    fn test_is_public_suffix_exception() {
        assert!(!is_public_suffix("www.ck"));
    }

    #[test]
    fn test_server_new() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };
        let server = Fido2Server::new(rp, None).unwrap();
        assert_eq!(server.rp_id(), "example.com");
        assert!(!server.allowed_algorithms.is_empty());
    }

    #[test]
    fn test_server_new_no_id() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: None,
        };
        assert!(Fido2Server::new(rp, None).is_err());
    }

    #[test]
    fn test_server_verify_origin() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };
        let server = Fido2Server::new(rp, None).unwrap();
        assert!(server.verify_origin("https://example.com"));
        assert!(server.verify_origin("https://www.example.com"));
        assert!(!server.verify_origin("http://example.com"));
        assert!(!server.verify_origin("https://evil.com"));
    }

    #[test]
    fn test_register_begin() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };
        let server = Fido2Server::new(rp, None).unwrap();

        let user = PublicKeyCredentialUserEntity {
            name: Some("alice".into()),
            id: b"alice-id".to_vec(),
            display_name: Some("Alice".into()),
        };

        let (options, state) = server
            .register_begin(user.clone(), None, None, None, None, None, None)
            .unwrap();

        assert_eq!(options.rp.name, "Example");
        assert_eq!(options.user.name, Some("alice".into()));
        assert_eq!(options.challenge.len(), 32);
        assert_eq!(state.challenge, options.challenge);
    }

    #[test]
    fn test_register_begin_custom_challenge() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };
        let server = Fido2Server::new(rp, None).unwrap();

        let user = PublicKeyCredentialUserEntity {
            name: Some("alice".into()),
            id: b"alice-id".to_vec(),
            display_name: None,
        };

        let challenge = b"1234567890123456";
        let (options, _) = server
            .register_begin(user, None, None, None, None, Some(challenge), None)
            .unwrap();
        assert_eq!(options.challenge, challenge);
    }

    #[test]
    fn test_register_begin_challenge_too_short() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };
        let server = Fido2Server::new(rp, None).unwrap();

        let user = PublicKeyCredentialUserEntity {
            name: Some("alice".into()),
            id: b"alice-id".to_vec(),
            display_name: None,
        };

        let result = server.register_begin(user, None, None, None, None, Some(b"short"), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_authenticate_begin() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example".into(),
            id: Some("example.com".into()),
        };
        let server = Fido2Server::new(rp, None).unwrap();

        let (options, state) = server.authenticate_begin(None, None, None, None).unwrap();

        assert_eq!(options.rp_id, Some("example.com".into()));
        assert_eq!(options.challenge.len(), 32);
        assert_eq!(state.challenge, options.challenge);
    }
}
