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

//! PRF (hmac-secret) extension example.
//!
//! Creates a credential with the hmac-secret extension enabled, then uses
//! it to derive secrets from salts. This demonstrates the CTAP2-level
//! hmac-secret extension which underlies the WebAuthn PRF extension.

use std::io::{self, Write};

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
    let devices = ctaphid::list_devices().expect("Failed to enumerate HID devices");

    // Find a device that supports hmac-secret
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
        if ctap
            .info()
            .extensions
            .iter()
            .any(|e| e == "hmac-secret")
        {
            println!(
                "Using device: {}",
                dev_info.product_name.as_deref().unwrap_or("Unknown")
            );
            drop(ctap);
            conn = Some(c);
            break;
        }
    }
    let conn = conn.expect("No FIDO device with hmac-secret support found!");
    let ctap = Ctap2::new(&conn, false).expect("Failed to initialize CTAP2");
    let info = ctap.info();

    let rp_id = "example.com";
    let interaction = CliInteraction::new();
    let client_data_hash = sha256(b"prf-example-client-data");

    // ---- Registration with hmac-secret ----

    let uv = "discouraged";
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

    let mut options_map = Vec::new();
    if internal_uv {
        options_map.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    // Enable hmac-secret extension
    let extensions = Value::Map(vec![(
        Value::Text("hmac-secret".into()),
        Value::Bool(true),
    )]);

    let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
        let client_pin = ClientPin::new(&ctap, None).unwrap();
        let param = client_pin.protocol().authenticate(token, &client_data_hash);
        (Some(param), Some(client_pin.protocol().version()))
    } else {
        (None, None)
    };

    println!("Creating a credential with hmac-secret (PRF) support...");

    let attestation = ctap
        .make_credential(
            &client_data_hash,
            rp_val,
            user_val,
            key_params,
            None,
            Some(extensions),
            if options_map.is_empty() {
                None
            } else {
                Some(Value::Map(options_map))
            },
            pin_uv_param.as_deref(),
            pin_uv_protocol,
            None,
            &mut on_keepalive,
        )
        .expect("makeCredential failed");

    // Check hmac-secret was enabled
    let hmac_enabled = attestation
        .auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.map_get_text("hmac-secret"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if hmac_enabled {
        println!("New credential created, with hmac-secret (PRF) extension.");
    } else {
        eprintln!("Warning: hmac-secret not confirmed in response, continuing anyway...");
    }

    // Extract credential ID for the allowList
    let cred_id = attestation
        .auth_data
        .credential_data
        .as_ref()
        .expect("No credential data")
        .credential_id
        .clone();

    // If UV was used, keep using it
    let uv = if attestation.auth_data.is_user_verified() {
        "required"
    } else {
        "discouraged"
    };

    // ---- Authentication with hmac-secret (single salt) ----

    // Generate a random salt
    let mut salt1 = [0u8; 32];
    getrandom::fill(&mut salt1).expect("Failed to generate salt");
    println!("Authenticate with salt: {}", fido2::logging::hex_encode(&salt1));

    let auth_client_data_hash = sha256(b"prf-example-auth-data");

    let use_uv_get = client::should_use_uv(info, Some(uv), client::permission::GET_ASSERTION)
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

    // Set up hmac-secret extension input:
    // The CTAP2 hmac-secret extension requires:
    //   1: keyAgreement (COSE key)
    //   2: saltEnc (encrypted salt(s))
    //   3: saltAuth (HMAC of saltEnc)
    //   4: pinUvAuthProtocol version
    let client_pin = ClientPin::new(&ctap, None).expect("Failed to create ClientPin");
    let (key_agreement, shared_secret) = client_pin
        ._get_shared_secret()
        .expect("Failed to get shared secret");
    let protocol = client_pin.protocol();

    // Encrypt salt1 (32 bytes)
    let salt_enc = protocol
        .encrypt(&shared_secret, &salt1)
        .expect("Failed to encrypt salt");
    let salt_auth = protocol.authenticate(&shared_secret, &salt_enc);

    let hmac_secret_input = Value::Map(vec![
        (Value::Int(1), key_agreement.to_value()),
        (Value::Int(2), Value::Bytes(salt_enc)),
        (Value::Int(3), Value::Bytes(salt_auth)),
        (Value::Int(4), Value::Int(protocol.version() as i64)),
    ]);

    let get_extensions = Value::Map(vec![(
        Value::Text("hmac-secret".into()),
        hmac_secret_input,
    )]);

    let mut get_options = Vec::new();
    if get_internal_uv {
        get_options.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    let (get_pin_param, get_pin_proto) = if let Some(ref token) = get_pin_token {
        let param = protocol.authenticate(token, &auth_client_data_hash);
        (Some(param), Some(protocol.version()))
    } else {
        (None, None)
    };

    let allow_list = Value::Array(vec![Value::Map(vec![
        (Value::Text("id".into()), Value::Bytes(cred_id.clone())),
        (
            Value::Text("type".into()),
            Value::Text("public-key".into()),
        ),
    ])]);

    println!("Authenticating with hmac-secret...");

    let assertion = ctap
        .get_assertion(
            rp_id,
            &auth_client_data_hash,
            Some(allow_list.clone()),
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

    // Decrypt the hmac-secret output
    let hmac_output_enc = assertion
        .auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.map_get_text("hmac-secret"))
        .and_then(|v| v.as_bytes())
        .expect("No hmac-secret output in assertion");

    let hmac_output = protocol
        .decrypt(&shared_secret, hmac_output_enc)
        .expect("Failed to decrypt hmac-secret output");

    let secret1 = &hmac_output[..32];
    println!("Authenticated, secret: {}", fido2::logging::hex_encode(secret1));

    // ---- Second authentication with two salts ----

    let mut salt2 = [0u8; 32];
    getrandom::fill(&mut salt2).expect("Failed to generate salt2");
    println!("Authenticate with second salt: {}", fido2::logging::hex_encode(&salt2));

    // Need fresh shared secret for each assertion
    let (key_agreement2, shared_secret2) = client_pin
        ._get_shared_secret()
        .expect("Failed to get shared secret");

    // Encrypt both salts (64 bytes total)
    let mut both_salts = salt1.to_vec();
    both_salts.extend_from_slice(&salt2);
    let salt_enc2 = protocol
        .encrypt(&shared_secret2, &both_salts)
        .expect("Failed to encrypt salts");
    let salt_auth2 = protocol.authenticate(&shared_secret2, &salt_enc2);

    let hmac_secret_input2 = Value::Map(vec![
        (Value::Int(1), key_agreement2.to_value()),
        (Value::Int(2), Value::Bytes(salt_enc2)),
        (Value::Int(3), Value::Bytes(salt_auth2)),
        (Value::Int(4), Value::Int(protocol.version() as i64)),
    ]);

    let get_extensions2 = Value::Map(vec![(
        Value::Text("hmac-secret".into()),
        hmac_secret_input2,
    )]);

    // Get fresh PIN/UV token
    let (get_pin_token2, get_internal_uv2) = if use_uv_get {
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

    let auth_client_data_hash2 = sha256(b"prf-example-auth-data-2");

    let mut get_options2 = Vec::new();
    if get_internal_uv2 {
        get_options2.push((Value::Text("uv".into()), Value::Bool(true)));
    }

    let (get_pin_param2, get_pin_proto2) = if let Some(ref token) = get_pin_token2 {
        let param = protocol.authenticate(token, &auth_client_data_hash2);
        (Some(param), Some(protocol.version()))
    } else {
        (None, None)
    };

    println!("Authenticating with two salts...");

    let assertion2 = ctap
        .get_assertion(
            rp_id,
            &auth_client_data_hash2,
            Some(allow_list),
            Some(get_extensions2),
            if get_options2.is_empty() {
                None
            } else {
                Some(Value::Map(get_options2))
            },
            get_pin_param2.as_deref(),
            get_pin_proto2,
            &mut on_keepalive,
        )
        .expect("getAssertion failed");

    let hmac_output_enc2 = assertion2
        .auth_data
        .extensions
        .as_ref()
        .and_then(|ext| ext.map_get_text("hmac-secret"))
        .and_then(|v| v.as_bytes())
        .expect("No hmac-secret output in assertion");

    let hmac_output2 = protocol
        .decrypt(&shared_secret2, hmac_output_enc2)
        .expect("Failed to decrypt hmac-secret output");

    let old_secret = &hmac_output2[..32];
    let new_secret = &hmac_output2[32..64];

    println!("Old secret (should match): {}", fido2::logging::hex_encode(old_secret));
    println!("New secret: {}", fido2::logging::hex_encode(new_secret));

    if old_secret == secret1 {
        println!("First secret matches across both assertions!");
    } else {
        eprintln!("Warning: First secret does not match!");
    }
}
