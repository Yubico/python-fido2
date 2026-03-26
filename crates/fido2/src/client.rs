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

//! FIDO2 client helpers.
//!
//! Provides [`ClientDataCollector`] for constructing `CollectedClientData`
//! and validating RP IDs against origins.

use crate::server::verify_rp_id;
use crate::webauthn::{client_data_type, CollectedClientData};

/// Errors returned by client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{0}")]
    BadRequest(String),
}

/// Collects client data and validates RP IDs for WebAuthn operations.
///
/// This is the Rust counterpart of `DefaultClientDataCollector` in Python.
pub struct ClientDataCollector {
    origin: String,
}

impl ClientDataCollector {
    /// Create a new collector for the given origin.
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
        }
    }

    /// Get the origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Extract the effective RP ID from request parameters.
    ///
    /// If `rp_id` is `None`, falls back to the host component of the origin.
    /// Returns an error if the origin is not HTTPS or has no host.
    pub fn get_rp_id(&self, rp_id: Option<&str>) -> Result<String, ClientError> {
        match rp_id {
            Some(id) => Ok(id.to_string()),
            None => {
                let parsed = url::Url::parse(&self.origin).map_err(|_| {
                    ClientError::BadRequest("RP ID required for non-https origin.".into())
                })?;
                if parsed.scheme() != "https" {
                    return Err(ClientError::BadRequest(
                        "RP ID required for non-https origin.".into(),
                    ));
                }
                parsed
                    .host_str()
                    .map(|h| h.to_string())
                    .ok_or_else(|| {
                        ClientError::BadRequest(
                            "RP ID required for non-https origin.".into(),
                        )
                    })
            }
        }
    }

    /// Verify that an RP ID is valid for this collector's origin.
    pub fn verify_rp_id(&self, rp_id: &str) -> Result<(), ClientError> {
        if verify_rp_id(rp_id, &self.origin) {
            Ok(())
        } else {
            Err(ClientError::BadRequest(
                "RP ID not valid for origin.".into(),
            ))
        }
    }

    /// Collect client data for a registration (webauthn.create) request.
    ///
    /// Returns `(CollectedClientData, rp_id)`.
    pub fn collect_create(
        &self,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> Result<(CollectedClientData, String), ClientError> {
        let rp_id = self.get_rp_id(rp_id)?;
        self.verify_rp_id(&rp_id)?;
        let cd = CollectedClientData::create(
            client_data_type::CREATE,
            challenge,
            &self.origin,
            false,
        );
        Ok((cd, rp_id))
    }

    /// Collect client data for an authentication (webauthn.get) request.
    ///
    /// Returns `(CollectedClientData, rp_id)`.
    pub fn collect_get(
        &self,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> Result<(CollectedClientData, String), ClientError> {
        let rp_id = self.get_rp_id(rp_id)?;
        self.verify_rp_id(&rp_id)?;
        let cd = CollectedClientData::create(
            client_data_type::GET,
            challenge,
            &self.origin,
            false,
        );
        Ok((cd, rp_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_rp_id_explicit() {
        let c = ClientDataCollector::new("https://example.com");
        assert_eq!(c.get_rp_id(Some("example.com")).unwrap(), "example.com");
    }

    #[test]
    fn test_get_rp_id_from_origin() {
        let c = ClientDataCollector::new("https://example.com");
        assert_eq!(c.get_rp_id(None).unwrap(), "example.com");
    }

    #[test]
    fn test_get_rp_id_http_requires_explicit() {
        let c = ClientDataCollector::new("http://example.com");
        assert!(c.get_rp_id(None).is_err());
    }

    #[test]
    fn test_verify_rp_id_valid() {
        let c = ClientDataCollector::new("https://example.com");
        assert!(c.verify_rp_id("example.com").is_ok());
    }

    #[test]
    fn test_verify_rp_id_invalid() {
        let c = ClientDataCollector::new("https://example.com");
        assert!(c.verify_rp_id("evil.com").is_err());
    }

    #[test]
    fn test_collect_create() {
        let c = ClientDataCollector::new("https://example.com");
        let (cd, rp_id) = c.collect_create(b"challenge_here__", Some("example.com")).unwrap();
        assert_eq!(rp_id, "example.com");
        assert_eq!(cd.type_, "webauthn.create");
        assert_eq!(cd.origin, "https://example.com");
        assert_eq!(cd.challenge, b"challenge_here__");
    }

    #[test]
    fn test_collect_get() {
        let c = ClientDataCollector::new("https://example.com");
        let (cd, rp_id) = c.collect_get(b"challenge_here__", None).unwrap();
        assert_eq!(rp_id, "example.com");
        assert_eq!(cd.type_, "webauthn.get");
    }

    #[test]
    fn test_collect_bad_rp_id() {
        let c = ClientDataCollector::new("https://example.com");
        assert!(c.collect_create(b"challenge_here__", Some("evil.com")).is_err());
    }
}
