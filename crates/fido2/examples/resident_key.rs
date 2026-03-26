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

//! Resident key (discoverable credential) example.
//!
//! Creates a discoverable credential and authenticates without an allow list.

mod common;

use fido2::client::Fido2Client;
use fido2::extensions::default_extensions;
use fido2::transport::ctaphid;
use fido2::webauthn::{
    AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, ResidentKeyRequirement,
    UserVerificationRequirement,
};

fn main() {
    let devices = ctaphid::list_devices().expect("Failed to enumerate HID devices");
    let dev_info = devices
        .first()
        .expect("No FIDO HID device found. Is your authenticator connected?");

    println!(
        "Using device: {}",
        dev_info.product_name.as_deref().unwrap_or("Unknown")
    );

    let conn = ctaphid::CtapHidConnection::open(dev_info).expect("Failed to open device");
    let interaction = common::CliInteraction::new();
    let client = Fido2Client::new(&conn, "https://example.com", &interaction, default_extensions())
        .expect("Failed to create client");

    // ---- Registration with rk=required ----
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
        challenge: b"registration-challenge".to_vec(),
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
        extensions: None,
    };

    println!("Creating a discoverable credential...");
    let result = client
        .make_credential(&create_options)
        .expect("Registration failed");

    let cred_data = result
        .attestation
        .auth_data
        .credential_data
        .as_ref()
        .expect("No credential data");

    println!("New discoverable credential created!");
    println!(
        "CREDENTIAL ID: {}",
        fido2::logging::hex_encode(&cred_data.credential_id)
    );

    // ---- Authentication without allow list (discoverable) ----
    let auth_options = PublicKeyCredentialRequestOptions {
        challenge: b"authentication-challenge".to_vec(),
        timeout: None,
        rp_id: Some("example.com".into()),
        allow_credentials: None, // No allow list — discoverable
        user_verification: Some(UserVerificationRequirement::Required),
        hints: None,
        extensions: None,
    };

    println!("Authenticating with discoverable credential...");
    let selection = client
        .get_assertion(&auth_options)
        .expect("Authentication failed");

    let (assertion, _ext_outputs) = selection.get(0);

    println!("Authenticated!");
    println!("UP: {}", assertion.auth_data.is_user_present());
    println!("UV: {}", assertion.auth_data.is_user_verified());
    println!("Sign count: {}", assertion.auth_data.counter);

    if let Some(ref user) = assertion.user {
        if let Some(user_id) = user.map_get_text("id").and_then(|v| v.as_bytes()) {
            println!("User ID: {}", fido2::logging::hex_encode(user_id));
        }
    }
}
