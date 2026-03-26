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

//! FIDO2 server verification logic.
//!
//! Provides RP ID validation against origins using the Public Suffix List,
//! and verification of registration and authentication responses.

use std::collections::HashSet;
use std::sync::LazyLock;

use crate::utils::bytes_eq;
use crate::webauthn::{
    AttestationObject, AuthenticatorData, AuthenticatorDataFlags, CollectedClientData,
};

// --- Error type ---

/// Errors returned by server verification functions.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("{0}")]
    Verification(String),
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
    // Check wildcard: if domain is "foo.bar" and "bar" is in wildcards
    if let Some((_label, parent)) = domain.split_once('.') {
        if psl.wildcards.contains(parent) {
            return true;
        }
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

// --- Registration verification ---

/// Verify a registration (webauthn.create) response.
///
/// Checks that the collected client data and attestation object are consistent
/// with the expected challenge, RP ID hash, and user verification requirements.
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

// --- Authentication verification ---

/// Verify an authentication (webauthn.get) response.
///
/// Checks that the collected client data and authenticator data are consistent
/// with the expected challenge, RP ID hash, and user verification requirements.
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
        // *.ck is in the PSL, so "foo.ck" should be a public suffix
        assert!(is_public_suffix("foo.ck"));
    }

    #[test]
    fn test_is_public_suffix_exception() {
        // !www.ck is an exception in the PSL
        assert!(!is_public_suffix("www.ck"));
    }
}
