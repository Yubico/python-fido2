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

//! Pseudo-Random Function (PRF) extension example.
//!
//! Uses the WebAuthn PRF extension (backed by hmac-secret) to derive
//! deterministic secrets from a credential.

mod common;

use fido2_client::client::Fido2Client;
use fido2_client::extensions::default_extensions;
use fido2_client::transport::ctaphid;
use fido2_server::webauthn::{
    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, ResidentKeyRequirement, UserVerificationRequirement,
};

fn main() {
    let devices = ctaphid::list_devices().expect("Failed to enumerate HID devices");

    // Find a device that supports hmac-secret
    let mut client = None;
    for dev_info in &devices {
        let c = match ctaphid::CtapHidConnection::open(dev_info) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let interaction = common::CliInteraction::new();
        let cl = match Fido2Client::new(
            c,
            "https://example.com",
            Box::new(interaction),
            default_extensions(false),
        ) {
            Ok(cl) => cl,
            Err(_) => continue,
        };
        if cl.info().extensions.iter().any(|e| e == "hmac-secret") {
            println!(
                "Using device: {}",
                dev_info.product_name.as_deref().unwrap_or("Unknown")
            );
            client = Some(cl);
            break;
        }
    }
    let mut client = client.expect("No FIDO device with hmac-secret support found!");

    // ---- Registration with prf ----
    let create_options = PublicKeyCredentialCreationOptions {
        rp: PublicKeyCredentialRpEntity {
            name: "Example RP".into(),
            id: Some("example.com".into()),
        },
        user: PublicKeyCredentialUserEntity {
            name: Some("A. User".into()),
            id: b"user_id".to_vec(),
            display_name: Some("A. User".into()),
        },
        challenge: b"prf-registration-challenge".to_vec(),
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        }],
        timeout: None,
        exclude_credentials: None,
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: Some(UserVerificationRequirement::Required),
            require_resident_key: None,
        }),
        hints: None,
        attestation: None,
        attestation_formats: None,
        extensions: Some(serde_json::json!({
            "prf": {},
        })),
    };

    println!("Creating a credential with PRF support...");
    let result = client
        .make_credential(&create_options)
        .expect("Registration failed");

    // Check prf enabled
    let prf_enabled = result
        .client_extension_results
        .as_ref()
        .and_then(|v| v.get("prf"))
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("PRF enabled: {}", prf_enabled);

    let cred_id = result.raw_id.clone();

    // ---- Evaluate PRF with a single salt ----
    let salt1 = fido2_server::utils::websafe_encode(b"example-prf-salt-1______________");
    let auth_options = PublicKeyCredentialRequestOptions {
        challenge: b"prf-auth-challenge".to_vec(),
        timeout: None,
        rp_id: Some("example.com".into()),
        allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: cred_id.clone(),
            transports: None,
        }]),
        user_verification: Some(UserVerificationRequirement::Required),
        hints: None,
        extensions: Some(serde_json::json!({
            "prf": {
                "eval": {
                    "first": salt1,
                }
            }
        })),
    };

    println!("\nEvaluating PRF with single salt...");
    let selection = client
        .get_assertion(&auth_options)
        .expect("Authentication failed");
    let response = selection.get_response(0);

    if let Some(prf) = response
        .client_extension_results
        .as_ref()
        .and_then(|v| v.get("prf"))
        && let Some(results) = prf.get("results")
        && let Some(first) = results.get("first").and_then(|v| v.as_str())
    {
        let bytes = fido2_server::utils::websafe_decode(first).unwrap();
        println!(
            "PRF output (first): {}",
            fido2_server::logging::hex_encode(&bytes)
        );
    }

    // ---- Evaluate PRF with two salts ----
    let salt2 = fido2_server::utils::websafe_encode(b"example-prf-salt-2______________");
    let auth_options2 = PublicKeyCredentialRequestOptions {
        challenge: b"prf-auth-challenge-2".to_vec(),
        timeout: None,
        rp_id: Some("example.com".into()),
        allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: cred_id.clone(),
            transports: None,
        }]),
        user_verification: Some(UserVerificationRequirement::Required),
        hints: None,
        extensions: Some(serde_json::json!({
            "prf": {
                "eval": {
                    "first": salt1,
                    "second": salt2,
                }
            }
        })),
    };

    println!("\nEvaluating PRF with two salts...");
    let selection = client
        .get_assertion(&auth_options2)
        .expect("Authentication failed");
    let response = selection.get_response(0);

    if let Some(prf) = response
        .client_extension_results
        .as_ref()
        .and_then(|v| v.get("prf"))
        && let Some(results) = prf.get("results")
    {
        if let Some(first) = results.get("first").and_then(|v| v.as_str()) {
            let bytes = fido2_server::utils::websafe_decode(first).unwrap();
            println!(
                "PRF output (first):  {}",
                fido2_server::logging::hex_encode(&bytes)
            );
        }
        if let Some(second) = results.get("second").and_then(|v| v.as_str()) {
            let bytes = fido2_server::utils::websafe_decode(second).unwrap();
            println!(
                "PRF output (second): {}",
                fido2_server::logging::hex_encode(&bytes)
            );
        }
    }
}
