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
//! Creates a resident key credential and authenticates without providing
//! an allowList, relying on the authenticator to discover the credential.

use std::io::{self, Write};

use fido2::cbor::Value;
use fido2::client::{self, UserInteraction};
use fido2::ctap::keepalive;
use fido2::ctap2::Ctap2;
use fido2::pin::ClientPin;
use fido2::server::Fido2Server;
use fido2::transport::ctaphid;
use fido2::webauthn::{
    AttestationObject, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};

struct CliInteraction {
    pin: std::cell::RefCell<Option<String>>,
}

impl CliInteraction {
    fn new() -> Self {
        Self {
            pin: std::cell::RefCell::new(None),
        }
    }
}

impl UserInteraction for CliInteraction {
    fn request_pin(&self, _permissions: u32, _rp_id: Option<&str>) -> Option<String> {
        let mut cached = self.pin.borrow_mut();
        if cached.is_none() {
            print!("Enter PIN: ");
            io::stdout().flush().ok();
            let mut pin = String::new();
            io::stdin().read_line(&mut pin).ok()?;
            *cached = Some(pin.trim().to_string());
        }
        cached.clone()
    }

    fn request_uv(&self, _permissions: u32, _rp_id: Option<&str>) -> bool {
        println!("User Verification required.");
        true
    }
}

fn on_keepalive(status: u8) {
    if status == keepalive::UPNEEDED {
        println!("\nTouch your authenticator device now...\n");
    }
}

fn main() {
    let devices = ctaphid::list_devices().expect("Failed to enumerate HID devices");

    // Find a device that supports resident keys
    let mut conn = None;
    for dev_info in &devices {
        let c = match ctaphid::CtapHidConnection::open(dev_info) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let ctap = match Ctap2::new(&c, false) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if ctap.info().options.get("rk") == Some(&true) {
            println!(
                "Using device: {}",
                dev_info.product_name.as_deref().unwrap_or("Unknown")
            );
            drop(ctap);
            conn = Some(c);
            break;
        }
    }
    let conn = conn.expect("No FIDO device with resident key support found!");
    let ctap = Ctap2::new(&conn, false).expect("Failed to initialize CTAP2");
    let info = ctap.info();

    let uv = if info.options.get("uv") == Some(&true)
        || info.options.get("bioEnroll") == Some(&true)
    {
        println!("Authenticator is configured for User Verification");
        "preferred"
    } else {
        "discouraged"
    };

    let rp_id = "example.com";
    let interaction = CliInteraction::new();

    let rp = PublicKeyCredentialRpEntity {
        name: "Example RP".into(),
        id: Some(rp_id.into()),
    };
    let server = Fido2Server::new(rp, None).expect("Failed to create server");

    let user = PublicKeyCredentialUserEntity {
        name: Some("A. User".into()),
        id: b"user_id".to_vec(),
        display_name: Some("A. User".into()),
    };

    // ---- Registration (resident key) ----

    let (create_options, reg_state) = server
        .register_begin(
            user,
            None,
            Some(fido2::webauthn::ResidentKeyRequirement::Required),
            None,
            None,
            None,
            None,
        )
        .expect("Failed to create registration options");

    let collector = fido2::client::ClientDataCollector::new("https://example.com");
    let (client_data, _) = collector
        .collect_create(&create_options.challenge, Some(rp_id))
        .expect("Failed to collect client data");
    let client_data_hash = client_data.hash();

    let use_uv = client::should_use_uv(info, Some(uv), client::permission::MAKE_CREDENTIAL)
        .expect("UV decision failed");

    let (pin_token, internal_uv) = if use_uv {
        let client_pin = ClientPin::new(&ctap, None).expect("Failed to create ClientPin");
        let token = client::get_token(
            info,
            &client_pin,
            client::permission::MAKE_CREDENTIAL,
            Some(rp_id),
            &mut on_keepalive,
            true,
            true,
            &interaction,
        )
        .expect("Failed to get PIN/UV token");
        let is_internal = token.is_none();
        (token, is_internal)
    } else {
        (None, false)
    };

    let rp_val = Value::Map(vec![
        (Value::Text("id".into()), Value::Text(rp_id.into())),
        (Value::Text("name".into()), Value::Text("Example RP".into())),
    ]);
    let user_val = Value::Map(vec![
        (
            Value::Text("id".into()),
            Value::Bytes(b"user_id".to_vec()),
        ),
        (Value::Text("name".into()), Value::Text("A. User".into())),
    ]);
    let key_params = Value::Array(vec![Value::Map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (Value::Text("alg".into()), Value::Int(-7)),
    ])]);

    // rk=true for resident key
    let mut options_map = vec![(Value::Text("rk".into()), Value::Bool(true))];
    if internal_uv {
        options_map.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
        let client_pin = ClientPin::new(&ctap, None).unwrap();
        let param = client_pin.protocol().authenticate(token, &client_data_hash);
        (Some(param), Some(client_pin.protocol().version()))
    } else {
        (None, None)
    };

    println!("Creating a resident key credential...");

    let attestation = ctap
        .make_credential(
            &client_data_hash,
            rp_val,
            user_val,
            key_params,
            None,
            None,
            Some(Value::Map(options_map)),
            pin_uv_param.as_deref(),
            pin_uv_protocol,
            None,
            &mut on_keepalive,
        )
        .expect("makeCredential failed");

    let att_obj =
        AttestationObject::create(&attestation.fmt, &attestation.auth_data, &attestation.att_stmt);
    let auth_data = server
        .register_complete(&reg_state, &client_data, &att_obj)
        .expect("Registration verification failed");

    let cred_data = auth_data
        .credential_data
        .as_ref()
        .expect("No credential data");

    println!("New resident key credential created!");
    println!("CREDENTIAL ID: {}", fido2::logging::hex_encode(&cred_data.credential_id));

    // ---- Authentication (discoverable, no allowList) ----

    let (auth_options, auth_state) = server
        .authenticate_begin(None, None, None, None)
        .expect("Failed to create authentication options");

    let (auth_client_data, _) = collector
        .collect_get(&auth_options.challenge, Some(rp_id))
        .expect("Failed to collect client data");
    let auth_client_data_hash = auth_client_data.hash();

    let use_uv_get =
        client::should_use_uv(info, Some(uv), client::permission::GET_ASSERTION)
            .expect("UV decision failed");

    let (get_pin_token, get_internal_uv) = if use_uv_get {
        let client_pin = ClientPin::new(&ctap, None).expect("Failed to create ClientPin");
        let token = client::get_token(
            info,
            &client_pin,
            client::permission::GET_ASSERTION,
            Some(rp_id),
            &mut on_keepalive,
            true,
            true,
            &interaction,
        )
        .expect("Failed to get PIN/UV token");
        let is_internal = token.is_none();
        (token, is_internal)
    } else {
        (None, false)
    };

    let mut get_options = Vec::new();
    if get_internal_uv {
        get_options.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    let (get_pin_param, get_pin_proto) = if let Some(ref token) = get_pin_token {
        let client_pin = ClientPin::new(&ctap, None).unwrap();
        let param = client_pin
            .protocol()
            .authenticate(token, &auth_client_data_hash);
        (Some(param), Some(client_pin.protocol().version()))
    } else {
        (None, None)
    };

    println!("Authenticating (discoverable, no allowList)...");

    // No allowList — authenticator discovers the credential
    let assertion = ctap
        .get_assertion(
            rp_id,
            &auth_client_data_hash,
            None,
            None,
            if get_options.is_empty() {
                None
            } else {
                Some(Value::Map(get_options))
            },
            get_pin_param.as_deref(),
            get_pin_proto,
            &mut on_keepalive,
        )
        .expect("getAssertion failed");

    // Extract credential ID from assertion response
    let assertion_cred_id = assertion
        .credential
        .map_get_text("id")
        .and_then(|v| v.as_bytes())
        .expect("No credential ID in assertion");

    let credentials = vec![(
        cred_data.credential_id.clone(),
        cred_data.public_key.clone(),
    )];

    server
        .authenticate_complete(
            &auth_state,
            &credentials,
            assertion_cred_id,
            &auth_client_data,
            &assertion.auth_data,
            &assertion.signature,
        )
        .expect("Authentication verification failed");

    println!("Credential authenticated!");

    // Show user handle from discoverable credential
    if let Some(user) = &assertion.user {
        if let Some(id) = user.map_get_text("id").and_then(|v| v.as_bytes()) {
            println!("USER ID: {:?}", String::from_utf8_lossy(id));
        }
    }
}
