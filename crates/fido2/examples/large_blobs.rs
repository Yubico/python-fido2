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

//! Large Blobs example.
//!
//! Connects to the first FIDO device found over USB HID, creates a new
//! credential with the largeBlobKey extension, then writes and reads back
//! a large blob using the CTAP2.1 Large Blobs API.

use std::io::{self, Write};

use fido2::blob::LargeBlobs;
use fido2::cbor::Value;
use fido2::client::{self, UserInteraction};
use fido2::ctap::keepalive;
use fido2::ctap2::Ctap2;
use fido2::pin::ClientPin;
use fido2::transport::ctaphid;
use fido2::utils::sha256;

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
    // Locate a FIDO HID device
    let devices = ctaphid::list_devices().expect("Failed to enumerate HID devices");
    let dev_info = devices
        .first()
        .expect("No FIDO HID device found. Is your authenticator connected?");

    println!(
        "Using device: {}",
        dev_info.product_name.as_deref().unwrap_or("Unknown")
    );

    let conn = ctaphid::CtapHidConnection::open(dev_info).expect("Failed to open device");
    let ctap = Ctap2::new(&conn, false).expect("Failed to initialize CTAP2");

    // Check for largeBlobKey + largeBlobs support
    let info = ctap.info();
    if !info.extensions.iter().any(|e| e == "largeBlobKey") {
        eprintln!("Error: Authenticator does not support largeBlobKey extension");
        std::process::exit(1);
    }
    if info.options.get("largeBlobs") != Some(&true) {
        eprintln!("Error: Authenticator does not support largeBlobs");
        std::process::exit(1);
    }

    // LargeBlob requires UV if PIN is configured
    let uv = if info.options.get("clientPin") == Some(&true) {
        "required"
    } else {
        "discouraged"
    };

    let interaction = CliInteraction::new();
    let rp_id = "example.com";
    let client_data_hash = sha256(b"example-client-data");

    // Determine UV and get PIN/UV token for makeCredential
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

    // Build CTAP2 makeCredential parameters
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
        (Value::Text("alg".into()), Value::Int(-7)), // ES256
    ])]);

    let mut options_map = vec![(Value::Text("rk".into()), Value::Bool(true))];
    if internal_uv {
        options_map.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    let extensions = Value::Map(vec![(
        Value::Text("largeBlobKey".into()),
        Value::Bool(true),
    )]);

    // Compute pin_uv_param over client_data_hash
    let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
        let client_pin = ClientPin::new(&ctap, None).unwrap();
        let param = client_pin.protocol().authenticate(token, &client_data_hash);
        (Some(param), Some(client_pin.protocol().version()))
    } else {
        (None, None)
    };

    println!("Creating a credential with LargeBlob support...");

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

    let large_blob_key = attestation
        .large_blob_key
        .as_ref()
        .expect("Credential does not have a largeBlobKey!");

    println!("Credential created! Writing a blob...");

    // ---- Write blob ----
    // Need a PIN/UV token with LARGE_BLOB_WRITE permission
    const LARGE_BLOB_WRITE: u32 = 0x10;
    let write_token = if use_uv {
        let client_pin = ClientPin::new(&ctap, None).unwrap();
        client::get_token(
            info,
            &client_pin,
            LARGE_BLOB_WRITE,
            Some(rp_id),
            &mut on_keepalive,
            false,
            true,
            &interaction,
        )
        .expect("Failed to get write token")
    } else {
        None
    };

    let client_pin = ClientPin::new(&ctap, None).ok();
    let protocol = client_pin.as_ref().map(|cp| cp.protocol());
    let large_blobs = LargeBlobs::new(&ctap, protocol, write_token.as_deref())
        .expect("Failed to create LargeBlobs");

    let blob_data = b"Here is some data to store!";
    large_blobs
        .put_blob(large_blob_key, Some(blob_data))
        .expect("Failed to write blob");

    println!("Blob written! Reading back the blob...");

    // ---- Read blob ----
    // Reading doesn't require a PIN/UV token
    let large_blobs_read =
        LargeBlobs::new(&ctap, None, None).expect("Failed to create LargeBlobs for reading");

    match large_blobs_read.get_blob(large_blob_key) {
        Ok(Some(data)) => println!("Read blob: {:?}", String::from_utf8_lossy(&data)),
        Ok(None) => println!("No blob found for this credential."),
        Err(e) => eprintln!("Failed to read blob: {e}"),
    }
}
