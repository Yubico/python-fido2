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

//! Credential Blob (credBlob) example.
//!
//! Creates a credential with the credBlob extension to store arbitrary data,
//! then reads it back during authentication.

mod common;

use fido2_client::client::Fido2Client;
use fido2_client::extensions::default_extensions;
use fido2_client::transport::ctaphid;
use fido2_server::webauthn::{
    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, ResidentKeyRequirement,
    UserVerificationRequirement,
};

fn main() {
    let devices = ctaphid::list_devices().expect("Failed to enumerate HID devices");

    // Find a device that supports credBlob
    let mut conn = None;
    for dev_info in &devices {
        let c = match ctaphid::CtapHidConnection::open(dev_info) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let interaction = common::CliInteraction::new();
        let client = match Fido2Client::new(
            &c,
            "https://example.com",
            &interaction,
            default_extensions(false),
        ) {
            Ok(cl) => cl,
            Err(_) => continue,
        };
        if client.info().extensions.iter().any(|e| e == "credBlob") {
            println!(
                "Using device: {}",
                dev_info.product_name.as_deref().unwrap_or("Unknown")
            );
            drop(client);
            conn = Some(c);
            break;
        }
    }
    let conn = conn.expect("No FIDO device with credBlob support found!");
    let interaction = common::CliInteraction::new();
    let client = Fido2Client::new(
        &conn,
        "https://example.com",
        &interaction,
        default_extensions(false),
    )
    .expect("Failed to create client");

    // Generate random blob data
    let mut blob = [0u8; 32];
    getrandom::fill(&mut blob).expect("Failed to generate random blob");

    // ---- Registration with credBlob ----
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
        challenge: b"cred-blob-challenge".to_vec(),
        pub_key_cred_params: vec![PublicKeyCredentialParameters {
            type_: PublicKeyCredentialType::PublicKey,
            alg: -7,
        }],
        timeout: None,
        exclude_credentials: None,
        authenticator_selection: Some(AuthenticatorSelectionCriteria {
            authenticator_attachment: None,
            resident_key: Some(ResidentKeyRequirement::Required),
            user_verification: Some(UserVerificationRequirement::Preferred),
            require_resident_key: None,
        }),
        hints: None,
        attestation: None,
        attestation_formats: None,
        extensions: Some(serde_json::json!({
            "credBlob": fido2_server::utils::websafe_encode(&blob),
        })),
    };

    println!("Creating a credential with credBlob...");
    println!("Blob data: {}", fido2_server::logging::hex_encode(&blob));

    let result = client
        .make_credential(&create_options)
        .expect("Registration failed");

    // Check credBlob was stored (via authenticator extensions in auth_data)
    let att_obj = result
        .response
        .attestation_object()
        .expect("Invalid attestation object");
    let cred_blob_stored = att_obj
        .auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.map_get_text("credBlob"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !cred_blob_stored {
        eprintln!("Credential was registered, but credBlob was NOT saved.");
        std::process::exit(1);
    }

    println!("New credential created, with the credBlob extension.");

    // ---- Authentication to read back credBlob ----
    let auth_options = PublicKeyCredentialRequestOptions {
        challenge: b"cred-blob-auth-challenge".to_vec(),
        timeout: None,
        rp_id: Some("example.com".into()),
        allow_credentials: None, // Discoverable
        user_verification: Some(UserVerificationRequirement::Preferred),
        hints: None,
        extensions: Some(serde_json::json!({
            "getCredBlob": true,
        })),
    };

    println!("Authenticating to read back credBlob...");
    let selection = client
        .get_assertion(&auth_options)
        .expect("Authentication failed");

    let response = selection.get_response(0);
    let auth_data = response
        .response
        .authenticator_data()
        .expect("Invalid authenticator data");

    // Read credBlob from assertion extensions
    let blob_result = auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.map_get_text("credBlob"))
        .and_then(|v| v.as_bytes());

    match blob_result {
        Some(result) if result == blob => {
            println!(
                "Authenticated, got correct blob: {}",
                fido2_server::logging::hex_encode(result)
            );
        }
        Some(result) => {
            eprintln!(
                "Authenticated, got incorrect blob! (was {}, expected {})",
                fido2_server::logging::hex_encode(result),
                fido2_server::logging::hex_encode(&blob)
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("Authenticated, but no credBlob in response!");
            std::process::exit(1);
        }
    }
}
