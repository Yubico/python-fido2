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

use std::io::{self, Write};

use fido2::cbor::Value;
use fido2::client::{self, UserInteraction};
use fido2::ctap::keepalive;
use fido2::ctap2::Ctap2;
use fido2::pin::ClientPin;
use fido2::transport::ctaphid;

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

    // Find a device that supports credBlob
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
        if ctap.info().extensions.iter().any(|e| e == "credBlob") {
            println!(
                "Using device: {}",
                dev_info.product_name.as_deref().unwrap_or("Unknown")
            );
            drop(ctap);
            conn = Some(c);
            break;
        }
    }
    let conn = conn.expect("No FIDO device with credBlob support found!");
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

    // ---- Registration with credBlob ----

    let use_uv = client::should_use_uv(info, Some(uv), client::permission::MAKE_CREDENTIAL)
        .expect("UV decision failed");

    let client_data_hash = fido2::utils::sha256(b"cred-blob-example-client-data");

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

    let mut options_map = vec![(Value::Text("rk".into()), Value::Bool(true))];
    if internal_uv {
        options_map.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    // Generate random blob data
    let mut blob = [0u8; 32];
    getrandom::fill(&mut blob).expect("Failed to generate random blob");

    // credBlob extension input: the blob data to store
    let extensions = Value::Map(vec![(
        Value::Text("credBlob".into()),
        Value::Bytes(blob.to_vec()),
    )]);

    let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
        let client_pin = ClientPin::new(&ctap, None).unwrap();
        let param = client_pin.protocol().authenticate(token, &client_data_hash);
        (Some(param), Some(client_pin.protocol().version()))
    } else {
        (None, None)
    };

    println!("Creating a credential with credBlob...");
    println!("Blob data: {}", fido2::logging::hex_encode(&blob));

    let attestation = ctap
        .make_credential(
            &client_data_hash,
            rp_val,
            user_val,
            key_params,
            None,
            Some(extensions),
            Some(Value::Map(options_map)),
            pin_uv_param.as_deref(),
            pin_uv_protocol,
            None,
            &mut on_keepalive,
        )
        .expect("makeCredential failed");

    // Check that credBlob was stored
    let cred_blob_stored = attestation
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

    let auth_client_data_hash = fido2::utils::sha256(b"cred-blob-example-auth-data");

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

    // Request credBlob in getAssertion extensions
    let get_extensions = Value::Map(vec![(
        Value::Text("credBlob".into()),
        Value::Bool(true),
    )]);

    println!("Authenticating to read back credBlob...");

    // Discoverable credential, no allowList
    let assertion = ctap
        .get_assertion(
            rp_id,
            &auth_client_data_hash,
            None,
            Some(get_extensions),
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

    // Read credBlob from assertion extensions
    let blob_result = assertion
        .auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.map_get_text("credBlob"))
        .and_then(|v| v.as_bytes());

    match blob_result {
        Some(result) if result == blob => {
            println!("Authenticated, got correct blob: {}", fido2::logging::hex_encode(result));
        }
        Some(result) => {
            eprintln!(
                "Authenticated, got incorrect blob! (was {}, expected {})",
                fido2::logging::hex_encode(result),
                fido2::logging::hex_encode(&blob)
            );
            std::process::exit(1);
        }
        None => {
            eprintln!("Authenticated, but no credBlob in response!");
            std::process::exit(1);
        }
    }
}
