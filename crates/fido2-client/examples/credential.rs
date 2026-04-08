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

//! Basic credential example.
//!
//! Connects to the first FIDO device found over USB HID, creates a new
//! credential, and authenticates it using the high-level Fido2Client API.

mod common;

use fido2_client::client::Fido2Client;
use fido2_client::extensions::default_extensions;
use fido2_client::transport::ctaphid;
use fido2_server::server::Fido2Server;
use fido2_server::webauthn::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
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
    let mut client = Fido2Client::new(
        conn,
        "https://example.com",
        Box::new(interaction),
        default_extensions(false),
    )
    .expect("Failed to create client");

    // Set up server
    let rp = PublicKeyCredentialRpEntity {
        name: "Example RP".into(),
        id: Some("example.com".into()),
    };
    let server = Fido2Server::new(rp, None).expect("Failed to create server");

    let user = PublicKeyCredentialUserEntity {
        name: Some("A. User".into()),
        id: b"user_id".to_vec(),
        display_name: Some("A. User".into()),
    };

    // ---- Registration ----
    let (create_options, reg_state) = server
        .register_begin(user, None, None, None, None, None, None)
        .expect("Failed to create registration options");

    println!("Creating a new credential...");
    let result = client
        .make_credential(&create_options)
        .expect("Registration failed");

    let client_data = result.response.client_data().expect("Invalid client data");
    let att_obj = result
        .response
        .attestation_object()
        .expect("Invalid attestation object");
    let auth_data = server
        .register_complete(&reg_state, &client_data, &att_obj)
        .expect("Registration verification failed");

    let cred_data = auth_data
        .credential_data
        .as_ref()
        .expect("No credential data");

    println!("New credential created!");
    println!(
        "CREDENTIAL ID: {}",
        fido2_server::logging::hex_encode(&cred_data.credential_id)
    );

    // ---- Authentication ----
    let (auth_options, auth_state) = server
        .authenticate_begin(
            Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred_data.credential_id.clone(),
                transports: None,
            }]),
            None,
            None,
            None,
        )
        .expect("Failed to create authentication options");

    println!("Authenticating...");
    let selection = client
        .get_assertion(&auth_options)
        .expect("Authentication failed");

    let response = selection.get_response(0);
    let client_data = response
        .response
        .client_data()
        .expect("Invalid client data");
    let auth_data = response
        .response
        .authenticator_data()
        .expect("Invalid authenticator data");

    let credentials = vec![(
        cred_data.credential_id.clone(),
        cred_data.public_key.clone(),
    )];
    server
        .authenticate_complete(
            &auth_state,
            &credentials,
            &response.raw_id,
            &client_data,
            &auth_data,
            &response.response.signature,
        )
        .expect("Authentication verification failed");

    println!("Credential authenticated!");
    println!("UP: {}", auth_data.is_user_present());
    println!("UV: {}", auth_data.is_user_verified());
    println!("Sign count: {}", auth_data.counter);
}
