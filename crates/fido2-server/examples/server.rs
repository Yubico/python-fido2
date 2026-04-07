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

//! Example WebAuthn demo server.
//!
//! Run with: `cargo run --example server`
//!
//! Then navigate to <http://localhost:5000> in a supported web browser.

use std::sync::Mutex;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use fido2_server::cose::CoseKey;
use fido2_server::server::{Fido2Server, ServerState};
use fido2_server::webauthn::{
    AuthenticationResponse, AuthenticatorAttachment, CredentialCreationOptions,
    CredentialRequestOptions, PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity,
    PublicKeyCredentialType, PublicKeyCredentialUserEntity, RegistrationResponse,
    UserVerificationRequirement,
};

// --- Application state ---

struct AppState {
    server: Fido2Server,
    credentials: Mutex<Vec<(Vec<u8>, CoseKey)>>,
    state: Mutex<Option<ServerState>>,
}

// --- Handlers ---

async fn index() -> Redirect {
    Redirect::to("/index.html")
}

async fn register_begin(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<Json<CredentialCreationOptions>, StatusCode> {
    let user = PublicKeyCredentialUserEntity {
        id: b"user_id".to_vec(),
        name: Some("a_user".into()),
        display_name: Some("A. User".into()),
    };

    let credentials = state.credentials.lock().unwrap();
    let exclude: Option<Vec<_>> = if credentials.is_empty() {
        None
    } else {
        Some(
            credentials
                .iter()
                .map(|(id, _)| PublicKeyCredentialDescriptor {
                    type_: PublicKeyCredentialType::PublicKey,
                    id: id.clone(),
                    transports: None,
                })
                .collect(),
        )
    };

    let (options, server_state) = state
        .server
        .register_begin(
            user,
            exclude,
            None,
            Some(UserVerificationRequirement::Discouraged),
            Some(AuthenticatorAttachment::CrossPlatform),
            None,
            None,
        )
        .map_err(|e| {
            eprintln!("register_begin error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    *state.state.lock().unwrap() = Some(server_state);

    Ok(Json(CredentialCreationOptions {
        public_key: options,
    }))
}

async fn register_complete(
    State(state): State<std::sync::Arc<AppState>>,
    Json(response): Json<RegistrationResponse>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let server_state = state
        .state
        .lock()
        .unwrap()
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let client_data = response.response.client_data().map_err(|e| {
        eprintln!("client_data parse error: {e}");
        StatusCode::BAD_REQUEST
    })?;
    let attestation_object = response.response.attestation_object().map_err(|e| {
        eprintln!("attestation_object parse error: {e}");
        StatusCode::BAD_REQUEST
    })?;

    let auth_data = state
        .server
        .register_complete(&server_state, &client_data, &attestation_object)
        .map_err(|e| {
            eprintln!("register_complete error: {e}");
            StatusCode::BAD_REQUEST
        })?;

    let cred_data = auth_data
        .credential_data
        .as_ref()
        .ok_or(StatusCode::BAD_REQUEST)?;

    println!(
        "Registered credential: {}",
        fido2_server::utils::websafe_encode(&cred_data.credential_id)
    );

    state.credentials.lock().unwrap().push((
        cred_data.credential_id.clone(),
        cred_data.public_key.clone(),
    ));

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

async fn authenticate_begin(
    State(state): State<std::sync::Arc<AppState>>,
) -> Result<Json<CredentialRequestOptions>, StatusCode> {
    let credentials = state.credentials.lock().unwrap();
    if credentials.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let allow: Vec<_> = credentials
        .iter()
        .map(|(id, _)| PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: id.clone(),
            transports: None,
        })
        .collect();

    let (options, server_state) = state
        .server
        .authenticate_begin(Some(allow), None, None, None)
        .map_err(|e| {
            eprintln!("authenticate_begin error: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    *state.state.lock().unwrap() = Some(server_state);

    Ok(Json(CredentialRequestOptions {
        public_key: options,
    }))
}

async fn authenticate_complete(
    State(state): State<std::sync::Arc<AppState>>,
    Json(response): Json<AuthenticationResponse>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let server_state = state
        .state
        .lock()
        .unwrap()
        .take()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let credentials = state.credentials.lock().unwrap();
    if credentials.is_empty() {
        return Err(StatusCode::NOT_FOUND);
    }

    let client_data = response.response.client_data().map_err(|e| {
        eprintln!("client_data parse error: {e}");
        StatusCode::BAD_REQUEST
    })?;
    let auth_data = response.response.authenticator_data().map_err(|e| {
        eprintln!("authenticator_data parse error: {e}");
        StatusCode::BAD_REQUEST
    })?;

    state
        .server
        .authenticate_complete(
            &server_state,
            &credentials,
            &response.raw_id,
            &client_data,
            &auth_data,
            &response.response.signature,
        )
        .map_err(|e| {
            eprintln!("authenticate_complete error: {e}");
            StatusCode::BAD_REQUEST
        })?;

    println!("Authentication successful");

    Ok(Json(serde_json::json!({ "status": "OK" })))
}

// --- Static files (embedded) ---

async fn serve_index_html() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn serve_register_html() -> Html<&'static str> {
    Html(REGISTER_HTML)
}

async fn serve_authenticate_html() -> Html<&'static str> {
    Html(AUTHENTICATE_HTML)
}

async fn serve_webauthn_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/javascript"),
        )],
        include_str!("static/webauthn-json.browser-ponyfill.js"),
    )
        .into_response()
}

const INDEX_HTML: &str = r#"<html>
<head>
  <title>WebAuthn demo</title>
  <style>
    body { font-family: sans-serif; line-height: 1.5em; padding: 2em 10em; }
    h1, h2 { color: #325F74; }
    a { color: #0080ac; font-weight: bold; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>WebAuthn demo using fido2-server (Rust)</h1>
  <p>This demo requires a browser supporting the WebAuthn API!</p>
  <hr>

  <h2>Available actions</h2>
  <a href="/register.html">Register</a><br>
  <a href="/authenticate.html">Authenticate</a><br>
</body>
</html>"#;

const REGISTER_HTML: &str = r#"<html>
<head>
  <title>WebAuthn demo - Register</title>

  <script type="module">
    import {
        create,
        parseCreationOptionsFromJSON,
    } from '/webauthn-json.browser-ponyfill.js';

    async function start() {
      let request = await fetch('/api/register/begin', {
        method: 'POST',
      });
      let json = await request.json();
      let options = parseCreationOptionsFromJSON(json);
      document.getElementById('initial').style.display = 'none';
      document.getElementById('started').style.display = 'block';

      let response = await create(options);
      let result = await fetch('/api/register/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(response),
      });

      let stat = result.ok ? 'successful' : 'unsuccessful';
      alert('Registration ' + stat);
      window.location = '/';
    }

    window.start = start;
  </script>

  <style>
    body { font-family: sans-serif; line-height: 1.5em; padding: 2em 10em; }
    h1, h2 { color: #325F74; }
    a { color: #0080ac; font-weight: bold; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>WebAuthn demo using fido2-server (Rust)</h1>
  <p>This demo requires a browser supporting the WebAuthn API!</p>
  <hr>

  <h2>Register a credential</h2>
  <div id="initial">
    <button onclick="start();">Click here to start</button>
  </div>
  <div id="started" style="display: none;">
    <p>Touch your authenticator device now...</p>
    <a href="/">Cancel</a>
  </div>
</body>
</html>"#;

const AUTHENTICATE_HTML: &str = r#"<html>
<head>
  <title>WebAuthn demo - Authenticate</title>

  <script type="module">
    import {
        get,
        parseRequestOptionsFromJSON,
    } from '/webauthn-json.browser-ponyfill.js';

    async function start() {
      let request = await fetch('/api/authenticate/begin', {
        method: 'POST',
      });
      if(!request.ok) {
        alert('No credential available to authenticate!');
        window.location = '/';
        return;
      }
      let json = await request.json();
      let options = parseRequestOptionsFromJSON(json);

      let response = await get(options);
      let result = await fetch('/api/authenticate/complete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(response),
      });

      let stat = result.ok ? 'successful' : 'unsuccessful';
      alert('Authentication ' + stat);
      window.location = '/';
    }

    window.start = start;
  </script>

  <style>
    body { font-family: sans-serif; line-height: 1.5em; padding: 2em 10em; }
    h1, h2 { color: #325F74; }
    a { color: #0080ac; font-weight: bold; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>WebAuthn demo using fido2-server (Rust)</h1>
  <p>This demo requires a browser supporting the WebAuthn API!</p>
  <hr>

  <h2>Authenticate using a credential</h2>
  <div id="initial">
    <button onclick="start();">Click here to start</button>
  </div>
  <div id="started" style="display: none;">
    <p>Touch your authenticator device now...</p>
    <a href="/">Cancel</a>
  </div>
</body>
</html>"#;

#[tokio::main]
async fn main() {
    let rp = PublicKeyCredentialRpEntity {
        name: "Demo server".into(),
        id: Some("localhost".into()),
    };
    let server = Fido2Server::new(rp, None).expect("Failed to create FIDO2 server");

    let app_state = std::sync::Arc::new(AppState {
        server,
        credentials: Mutex::new(Vec::new()),
        state: Mutex::new(None),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/index.html", get(serve_index_html))
        .route("/register.html", get(serve_register_html))
        .route("/authenticate.html", get(serve_authenticate_html))
        .route("/webauthn-json.browser-ponyfill.js", get(serve_webauthn_js))
        .route("/api/register/begin", post(register_begin))
        .route("/api/register/complete", post(register_complete))
        .route("/api/authenticate/begin", post(authenticate_begin))
        .route("/api/authenticate/complete", post(authenticate_complete))
        .with_state(app_state);

    println!("WebAuthn demo server using fido2-server (Rust)");
    println!("Navigate to http://localhost:5000 in a supported web browser.");

    let listener = tokio::net::TcpListener::bind("localhost:5000")
        .await
        .expect("Failed to bind to localhost:5000");
    axum::serve(listener, app).await.expect("Server error");
}
