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

//! Large Blob Storage (largeBlob) example.
//!
//! Creates a credential with largeBlobKey support, writes a blob via the
//! largeBlob extension during authentication, then reads it back.

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

    // Find a device that supports largeBlobs
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
        if client.info().options.get("largeBlobs") == Some(&true) {
            println!(
                "Using device: {}",
                dev_info.product_name.as_deref().unwrap_or("Unknown")
            );
            drop(client);
            conn = Some(c);
            break;
        }
    }
    let conn = conn.expect("No FIDO device with largeBlob support found!");
    let interaction = common::CliInteraction::new();
    let client = Fido2Client::new(
        &conn,
        "https://example.com",
        &interaction,
        default_extensions(false),
    )
    .expect("Failed to create client");

    // ---- Registration with largeBlob support ----
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
        challenge: b"large-blob-challenge".to_vec(),
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
            "largeBlob": { "support": "required" },
        })),
    };

    println!("Creating a credential with largeBlob support...");
    let result = client
        .make_credential(&create_options)
        .expect("Registration failed");

    // Check largeBlob extension output
    let supported = result
        .extension_outputs
        .get("largeBlob")
        .and_then(|v| v.map_get_text("supported"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("largeBlob supported: {}", supported);

    let cred_data = result
        .attestation
        .auth_data
        .credential_data
        .as_ref()
        .expect("No credential data");

    let cred_id = &cred_data.credential_id;

    // ---- Write a blob ----
    let blob_data = b"Hello from Rust large blob!";
    let write_options = PublicKeyCredentialRequestOptions {
        challenge: b"write-blob-challenge".to_vec(),
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
            "largeBlob": { "write": fido2_server::utils::websafe_encode(blob_data) },
        })),
    };

    println!("Writing large blob...");
    let result = client
        .get_assertion(&write_options)
        .expect("Write assertion failed");
    let ext_outputs = &result.extension_outputs[0];

    let written = ext_outputs
        .get("largeBlob")
        .and_then(|v| v.map_get_text("written"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    println!("Blob written: {}", written);

    // ---- Read the blob back ----
    let read_options = PublicKeyCredentialRequestOptions {
        challenge: b"read-blob-challenge".to_vec(),
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
            "largeBlob": { "read": true },
        })),
    };

    println!("Reading large blob...");
    let result = client
        .get_assertion(&read_options)
        .expect("Read assertion failed");
    let ext_outputs = &result.extension_outputs[0];

    let read_blob = ext_outputs
        .get("largeBlob")
        .and_then(|v| v.map_get_text("blob"))
        .and_then(|v| v.as_bytes());

    match read_blob {
        Some(data) if data == blob_data => {
            println!("Read back correct blob: {:?}", std::str::from_utf8(data));
        }
        Some(data) => {
            eprintln!("Read back incorrect blob: {:?}", data);
            std::process::exit(1);
        }
        None => {
            eprintln!("No blob data in response!");
            std::process::exit(1);
        }
    }
}
