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

//! FIDO2 client with CTAP1 and CTAP2 backend support.
//!
//! Provides [`Fido2Client`] — a high-level WebAuthn client that automatically
//! selects between CTAP1 (U2F) and CTAP2 backends based on device capabilities.

use std::time::Duration;

use crate::ctap::{ApduError, CtapDevice, CtapError, CtapStatus, apdu, capability, keepalive};
use crate::ctap1;
use crate::ctap2::{self, AssertionResponse, AttestationResponse, Info};
use crate::extensions::{
    AuthenticationExtensionProcessor, Ctap2Extension, ExtensionInputs, ExtensionOutputs,
    RegistrationExtensionProcessor,
};
use crate::pin::{ClientPin, PinProtocol};
use fido2_server::cbor::Value;
use fido2_server::cose::Algorithm;
use fido2_server::server::verify_rp_id;
use fido2_server::utils::sha256;
use fido2_server::utils::websafe_encode;
use fido2_server::webauthn::{
    self, Aaguid, AttestationConveyancePreference, AttestationObject, AuthenticationResponse,
    AuthenticatorAssertionResponse, AuthenticatorAttachment, AuthenticatorAttestationResponse,
    CollectedClientData, PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialType, RegistrationResponse,
    ResidentKeyRequirement, UserVerificationRequirement,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    ConfigurationUnsupported(String),
    #[error("PIN required but not provided")]
    PinRequired,
    #[error("Device ineligible")]
    DeviceIneligible,
    #[error("Operation timed out")]
    Timeout,
    #[error("CTAP error: {0}")]
    Ctap(#[from] CtapError),
}

// ---------------------------------------------------------------------------
// User interaction
// ---------------------------------------------------------------------------

/// User interaction trait for PIN/UV prompts.
pub trait UserInteraction {
    fn request_pin(&self, permissions: u32, rp_id: Option<&str>) -> Option<String>;
    fn request_uv(&self, permissions: u32, rp_id: Option<&str>) -> bool;
    fn prompt_up(&self) {}
}

// ---------------------------------------------------------------------------
// UV / PIN helpers
// ---------------------------------------------------------------------------

/// User verification requirement values.
pub mod uv_requirement {
    pub const REQUIRED: &str = "required";
    pub const PREFERRED: &str = "preferred";
    pub const DISCOURAGED: &str = "discouraged";
}

/// ClientPin permission flags.
pub mod permission {
    pub const MAKE_CREDENTIAL: u32 = 0x01;
    pub const GET_ASSERTION: u32 = 0x02;
}

/// Determine whether user verification should be performed.
pub fn should_use_uv(
    info: &Info,
    user_verification: Option<&str>,
    permissions: u32,
) -> Result<bool, ClientError> {
    let uv_supported = info.options.contains_key("uv")
        || info.options.contains_key("clientPin")
        || info.options.contains_key("bioEnroll");

    let uv_configured = info.options.get("uv").copied().unwrap_or(false)
        || info.options.get("clientPin").copied().unwrap_or(false)
        || info.options.get("bioEnroll").copied().unwrap_or(false);

    let mc = permissions & permission::MAKE_CREDENTIAL != 0;
    let additional_perms = permissions & !(permission::MAKE_CREDENTIAL | permission::GET_ASSERTION);

    if user_verification == Some(uv_requirement::REQUIRED)
        || (matches!(user_verification, Some(uv_requirement::PREFERRED) | None) && uv_supported)
        || info.options.get("alwaysUv").copied().unwrap_or(false)
    {
        if !uv_configured {
            return Err(ClientError::ConfigurationUnsupported(
                "User verification not configured/supported".into(),
            ));
        }
        return Ok(true);
    } else if uv_configured
        && (additional_perms != 0
            || mc
                && !info
                    .options
                    .get("makeCredUvNotRqd")
                    .copied()
                    .unwrap_or(false))
    {
        return Ok(true);
    }
    Ok(false)
}

/// Filter a credential list against the authenticator.
pub fn filter_creds<D: CtapDevice>(
    ctap: &mut ctap2::Ctap2<D>,
    rp_id: &str,
    cred_list: &[Value],
    pin_auth: Option<&[u8]>,
    pin_version: Option<u32>,
    on_keepalive: &mut dyn FnMut(u8),
) -> Result<Option<Value>, CtapError> {
    let info = ctap.get_info()?;

    let max_len = info.max_cred_id_length;
    let filtered: Vec<&Value> = if max_len > 0 {
        cred_list
            .iter()
            .filter(|c| {
                if let Value::Map(entries) = c {
                    for (k, v) in entries {
                        if k.as_text() == Some("id")
                            && let Some(id_bytes) = v.as_bytes()
                        {
                            return id_bytes.len() <= max_len;
                        }
                    }
                }
                true
            })
            .collect()
    } else {
        cred_list.iter().collect()
    };

    if filtered.is_empty() {
        return Ok(None);
    }

    let client_data_hash = [0u8; 32];
    let options = Value::Map(vec![(Value::Text("up".to_string()), Value::Bool(false))]);

    let mut max_creds = if info.max_creds_in_list > 0 {
        info.max_creds_in_list
    } else {
        1
    };

    let mut remaining = &filtered[..];
    while !remaining.is_empty() {
        let chunk_size = max_creds.min(remaining.len());
        let chunk = &remaining[..chunk_size];

        let allow_list = Value::Array(chunk.iter().map(|c| (*c).clone()).collect());

        match ctap.get_assertion(
            rp_id,
            &client_data_hash,
            Some(allow_list),
            None,
            Some(options.clone()),
            pin_auth,
            pin_version,
            on_keepalive,
            None,
        ) {
            Ok(assertion) => {
                if chunk.len() == 1 {
                    return Ok(Some(chunk[0].clone()));
                } else {
                    return Ok(Some(assertion.credential));
                }
            }
            Err(CtapError::StatusError(CtapStatus::RequestTooLarge)) if max_creds > 1 => {
                max_creds -= 1;
            }
            Err(CtapError::StatusError(CtapStatus::NoCredentials)) => {
                remaining = &remaining[chunk_size..];
            }
            Err(e) => return Err(e),
        }
    }

    Ok(None)
}

/// Get a PIN/UV token from the authenticator.
#[allow(clippy::too_many_arguments)]
pub fn get_token<D: CtapDevice>(
    info: &Info,
    client_pin: &mut ClientPin<D>,
    permissions: u32,
    rp_id: Option<&str>,
    on_keepalive: &mut dyn FnMut(u8),
    allow_internal_uv: bool,
    allow_uv: bool,
    user_interaction: &dyn UserInteraction,
) -> Result<Option<Vec<u8>>, ClientError> {
    if allow_uv && info.options.get("uv").copied().unwrap_or(false) {
        if info.options.get("pinUvAuthToken").copied() == Some(true) {
            if user_interaction.request_uv(permissions, rp_id) {
                let token = client_pin.get_uv_token(permissions, rp_id, on_keepalive, None)?;
                return Ok(Some(token));
            }
        } else if allow_internal_uv && user_interaction.request_uv(permissions, rp_id) {
            return Ok(None);
        }
    }

    if info.options.get("clientPin").copied().unwrap_or(false) {
        if let Some(pin) = user_interaction.request_pin(permissions, rp_id)
            && !pin.is_empty()
        {
            let token = client_pin.get_pin_token(&pin, Some(permissions), rp_id)?;
            return Ok(Some(token));
        }
        return Err(ClientError::PinRequired);
    }

    Err(ClientError::ConfigurationUnsupported(
        "User verification not configured".into(),
    ))
}

/// Get auth parameters (pin_token, internal_uv) for a CTAP2 operation.
///
/// Takes ownership of the `Ctap2` to create a temporary `ClientPin`, then
/// returns the `Ctap2` back along with the result.
#[allow(clippy::too_many_arguments)]
pub fn get_auth_params<D: CtapDevice>(
    mut ctap: ctap2::Ctap2<D>,
    rp_id: &str,
    user_verification: Option<&str>,
    permissions: u32,
    allow_uv: bool,
    on_keepalive: &mut dyn FnMut(u8),
    user_interaction: &dyn UserInteraction,
    pin_protocol_version: Option<u32>,
) -> Result<(ctap2::Ctap2<D>, Option<Vec<u8>>, bool), ClientError> {
    let info = ctap.get_info()?;

    let mut pin_token = None;
    let mut internal_uv = false;

    if should_use_uv(&info, user_verification, permissions)? {
        let protocol = pin_protocol_version
            .and_then(|v| match v {
                1 => Some(PinProtocol::V1),
                2 => Some(PinProtocol::V2),
                _ => None,
            })
            .ok_or_else(|| {
                ClientError::ConfigurationUnsupported("No PIN/UV protocol available".into())
            })?;
        let mut client_pin = ClientPin::new(ctap, Some(protocol))?;

        let allow_internal_uv =
            permissions & !(permission::MAKE_CREDENTIAL | permission::GET_ASSERTION) == 0;

        let token = get_token(
            &info,
            &mut client_pin,
            permissions,
            Some(rp_id),
            on_keepalive,
            allow_internal_uv,
            allow_uv,
            user_interaction,
        )?;

        if token.is_none() {
            internal_uv = true;
        }
        pin_token = token;
        ctap = client_pin.into_ctap();
    }

    Ok((ctap, pin_token, internal_uv))
}

// ---------------------------------------------------------------------------
// ClientDataCollector
// ---------------------------------------------------------------------------

/// Collects client data and validates RP IDs for WebAuthn operations.
pub struct ClientDataCollector {
    origin: String,
}

impl ClientDataCollector {
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
        }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn get_rp_id(&self, rp_id: Option<&str>) -> Result<String, ClientError> {
        match rp_id {
            Some(id) => Ok(id.to_string()),
            None => {
                let parsed = url::Url::parse(&self.origin).map_err(|_| {
                    ClientError::BadRequest("RP ID required for non-https origin.".into())
                })?;
                if parsed.scheme() != "https" {
                    return Err(ClientError::BadRequest(
                        "RP ID required for non-https origin.".into(),
                    ));
                }
                parsed.host_str().map(|h| h.to_string()).ok_or_else(|| {
                    ClientError::BadRequest("RP ID required for non-https origin.".into())
                })
            }
        }
    }

    pub fn verify_rp_id(&self, rp_id: &str) -> Result<(), ClientError> {
        if verify_rp_id(rp_id, &self.origin) {
            Ok(())
        } else {
            Err(ClientError::BadRequest(
                "RP ID not valid for origin.".into(),
            ))
        }
    }

    pub fn collect_create(
        &self,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> Result<(CollectedClientData, String), ClientError> {
        let rp_id = self.get_rp_id(rp_id)?;
        self.verify_rp_id(&rp_id)?;
        let cd = CollectedClientData::create(
            webauthn::client_data_type::CREATE,
            challenge,
            &self.origin,
            false,
        );
        Ok((cd, rp_id))
    }

    pub fn collect_get(
        &self,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> Result<(CollectedClientData, String), ClientError> {
        let rp_id = self.get_rp_id(rp_id)?;
        self.verify_rp_id(&rp_id)?;
        let cd = CollectedClientData::create(
            webauthn::client_data_type::GET,
            challenge,
            &self.origin,
            false,
        );
        Ok((cd, rp_id))
    }
}

// ---------------------------------------------------------------------------
// Backend trait
// ---------------------------------------------------------------------------

/// Result of a get_assertion operation, providing access to individual assertions
/// and their corresponding `AuthenticationResponse` representations.
pub struct AssertionSelection {
    client_data: CollectedClientData,
    assertions: Vec<AssertionResponse>,
    extension_outputs: Vec<ExtensionOutputs>,
}

impl AssertionSelection {
    /// Get the raw CTAP assertion responses.
    pub fn get_assertions(&self) -> &[AssertionResponse] {
        &self.assertions
    }

    /// Build an `AuthenticationResponse` for the assertion at the given index.
    pub fn get_response(&self, index: usize) -> AuthenticationResponse {
        let assertion = &self.assertions[index];
        let extension_outputs = &self.extension_outputs[index];

        let credential_id = assertion
            .credential
            .map_get_text("id")
            .and_then(|v| v.as_bytes())
            .unwrap_or(&[])
            .to_vec();

        let user_handle = assertion.user.as_ref().and_then(|u| {
            u.map_get_text("id")
                .and_then(|v| v.as_bytes())
                .map(|b| b.to_vec())
        });

        let client_extension_results = if extension_outputs.is_empty() {
            None
        } else {
            cbor_map_to_json(extension_outputs)
        };

        AuthenticationResponse {
            id: websafe_encode(&credential_id),
            raw_id: credential_id,
            response: AuthenticatorAssertionResponse {
                client_data_json: self.client_data.as_bytes().to_vec(),
                authenticator_data: assertion.auth_data.as_bytes().to_vec(),
                signature: assertion.signature.clone(),
                user_handle,
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            client_extension_results,
            type_: Some(PublicKeyCredentialType::PublicKey),
        }
    }
}

/// Convert a CBOR extension outputs map to a JSON value.
fn cbor_map_to_json(map: &ExtensionOutputs) -> Option<serde_json::Value> {
    let mut json_map = serde_json::Map::new();
    for (k, v) in map {
        json_map.insert(k.clone(), cbor_to_json(v));
    }
    Some(serde_json::Value::Object(json_map))
}

fn cbor_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Int(n) => serde_json::json!(n),
        Value::Bool(b) => serde_json::json!(b),
        Value::Text(s) => serde_json::json!(s),
        Value::Bytes(b) => serde_json::json!(websafe_encode(b)),
        Value::Array(arr) => serde_json::Value::Array(arr.iter().map(cbor_to_json).collect()),
        Value::Map(entries) => {
            let mut m = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    Value::Text(s) => s.clone(),
                    Value::Int(n) => n.to_string(),
                    _ => continue,
                };
                m.insert(key, cbor_to_json(v));
            }
            serde_json::Value::Object(m)
        }
    }
}

/// Backend abstraction for FIDO client operations.
///
/// Implemented by [`Ctap1Backend`] (U2F) and [`Ctap2Backend`] (CTAP2).
pub trait ClientBackend {
    /// Get authenticator information.
    fn info(&self) -> &Info;

    /// Perform authenticator selection (touch).
    fn selection(&mut self) -> Result<(), ClientError>;

    /// Create a credential with pre-computed client data hash and RP ID.
    fn do_make_credential(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<(AttestationResponse, ExtensionOutputs), ClientError>;

    /// Get assertions with pre-computed client data hash and RP ID.
    fn do_get_assertion(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<(Vec<AssertionResponse>, Vec<ExtensionOutputs>), ClientError>;
}

// ---------------------------------------------------------------------------
// CTAP1 backend
// ---------------------------------------------------------------------------

/// Default poll delay for CTAP1 operations.
const CTAP1_POLL_DELAY: Duration = Duration::from_millis(250);

/// CTAP1/U2F backend.
pub struct Ctap1Backend<D: CtapDevice> {
    ctap1: ctap1::Ctap1<D>,
    info: Info,
    interaction: Box<dyn UserInteraction>,
}

impl<D: CtapDevice> Ctap1Backend<D> {
    pub fn new(device: D, interaction: Box<dyn UserInteraction>) -> Self {
        let ctap1 = ctap1::Ctap1::new(device);
        let info = Info {
            versions: vec!["U2F_V2".into()],
            aaguid: Aaguid::NONE,
            ..Info::from_cbor(&[])
        };
        Self {
            ctap1,
            info,
            interaction,
        }
    }

    /// Consume and return the owned device.
    pub fn into_device(self) -> D {
        self.ctap1.into_device()
    }

    /// Poll a CTAP1 operation until it succeeds or fails.
    fn call_polling<F, T>(&mut self, mut func: F) -> Result<T, ClientError>
    where
        F: FnMut(&mut ctap1::Ctap1<D>) -> Result<T, ApduError>,
    {
        let mut prompted = false;
        loop {
            match func(&mut self.ctap1) {
                Ok(result) => return Ok(result),
                Err(e) if e.code == apdu::USE_NOT_SATISFIED => {
                    if !prompted {
                        self.interaction.prompt_up();
                        prompted = true;
                    }
                    std::thread::sleep(CTAP1_POLL_DELAY);
                }
                Err(e) => {
                    return Err(ClientError::BadRequest(format!(
                        "APDU error: 0x{:04X}",
                        e.code
                    )));
                }
            }
        }
    }
}

impl<D: CtapDevice> ClientBackend for Ctap1Backend<D> {
    fn info(&self) -> &Info {
        &self.info
    }

    fn selection(&mut self) -> Result<(), ClientError> {
        let dummy = [0u8; 32];
        self.call_polling(|ctap1| ctap1.register(&dummy, &dummy))?;
        Ok(())
    }

    fn do_make_credential(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<(AttestationResponse, ExtensionOutputs), ClientError> {
        let selection = options.authenticator_selection.as_ref();
        let uv_requirement = selection.and_then(|s| s.user_verification.as_ref());
        let rk_requirement = selection.and_then(|s| s.resident_key.as_ref());

        if rk_requirement == Some(&ResidentKeyRequirement::Required) {
            return Err(ClientError::ConfigurationUnsupported(
                "Resident key not supported by U2F".into(),
            ));
        }
        if uv_requirement == Some(&UserVerificationRequirement::Required) {
            return Err(ClientError::ConfigurationUnsupported(
                "User verification not supported by U2F".into(),
            ));
        }
        if options.attestation == Some(AttestationConveyancePreference::Enterprise) {
            return Err(ClientError::ConfigurationUnsupported(
                "Enterprise attestation not supported by U2F".into(),
            ));
        }

        let has_es256 = options
            .pub_key_cred_params
            .iter()
            .any(|p| p.alg == Algorithm::ES256 as i64);
        if !has_es256 {
            return Err(ClientError::ConfigurationUnsupported(
                "ES256 algorithm required for U2F".into(),
            ));
        }

        let app_param = sha256(rp_id.as_bytes());

        // Check exclude list
        if let Some(ref exclude_list) = options.exclude_credentials {
            let dummy_param = [0u8; 32];
            for cred in exclude_list {
                match self
                    .ctap1
                    .authenticate(&dummy_param, &app_param, &cred.id, true)
                {
                    Err(e) if e.code == apdu::USE_NOT_SATISFIED => {
                        // Credential exists — register with dummy to prompt UP, then fail
                        self.call_polling(|ctap1| ctap1.register(&dummy_param, &dummy_param))?;
                        return Err(ClientError::DeviceIneligible);
                    }
                    _ => {}
                }
            }
        }

        let registration =
            self.call_polling(|ctap1| ctap1.register(client_data_hash, &app_param))?;

        let att_resp = AttestationResponse::from_ctap1(&app_param, &registration)
            .map_err(|e| ClientError::BadRequest(e.to_string()))?;

        Ok((att_resp, ExtensionOutputs::new()))
    }

    fn do_get_assertion(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<(Vec<AssertionResponse>, Vec<ExtensionOutputs>), ClientError> {
        let uv_requirement = options.user_verification.as_ref();

        if uv_requirement == Some(&UserVerificationRequirement::Required) {
            return Err(ClientError::ConfigurationUnsupported(
                "User verification not supported by U2F".into(),
            ));
        }

        let allow_list = options.allow_credentials.as_ref().ok_or_else(|| {
            ClientError::ConfigurationUnsupported(
                "allow_credentials required for U2F authentication".into(),
            )
        })?;

        if allow_list.is_empty() {
            return Err(ClientError::DeviceIneligible);
        }

        let app_param = sha256(rp_id.as_bytes());

        for cred in allow_list {
            match self.call_polling(|ctap1| {
                ctap1.authenticate(client_data_hash, &app_param, &cred.id, false)
            }) {
                Ok(sig_data) => {
                    let cred_cbor = cred.to_cbor_value();
                    let assertion = AssertionResponse::from_ctap1(
                        &app_param,
                        cred_cbor,
                        sig_data.user_presence,
                        sig_data.counter,
                        &sig_data.signature,
                    );
                    return Ok((vec![assertion], vec![ExtensionOutputs::new()]));
                }
                Err(ClientError::Timeout) => return Err(ClientError::Timeout),
                Err(_) => continue,
            }
        }

        Err(ClientError::DeviceIneligible)
    }
}

// ---------------------------------------------------------------------------
// CTAP2 backend
// ---------------------------------------------------------------------------

/// Negotiate the PIN/UV protocol version from authenticator info.
fn negotiate_pin_protocol(info: &Info) -> Option<PinProtocol> {
    if info.pin_uv_protocols.contains(&2) {
        Some(PinProtocol::V2)
    } else if info.pin_uv_protocols.contains(&1) {
        Some(PinProtocol::V1)
    } else {
        None
    }
}

/// Merge extension inputs into a single CBOR Value.
fn merge_extension_inputs(inputs: &ExtensionInputs) -> Value {
    Value::Map(
        inputs
            .iter()
            .map(|(k, v)| (Value::Text(k.clone()), v.clone()))
            .collect(),
    )
}

/// CTAP2 backend.
pub struct Ctap2Backend<D: CtapDevice> {
    ctap: Option<ctap2::Ctap2<D>>,
    extensions: Vec<Box<dyn Ctap2Extension<D>>>,
    interaction: Box<dyn UserInteraction>,
    enterprise_rpid_list: Option<Vec<String>>,
}

impl<D: CtapDevice> Ctap2Backend<D> {
    pub fn new(
        device: D,
        interaction: Box<dyn UserInteraction>,
        extensions: Vec<Box<dyn Ctap2Extension<D>>>,
    ) -> Result<Self, CtapError> {
        let ctap = ctap2::Ctap2::new(device, false)?;
        Ok(Self {
            ctap: Some(ctap),
            extensions,
            interaction,
            enterprise_rpid_list: None,
        })
    }

    /// Consume and return the owned Ctap2.
    pub fn into_ctap(mut self) -> ctap2::Ctap2<D> {
        self.ctap.take().expect("Ctap2 already taken")
    }

    /// Consume and return the owned device.
    pub fn into_device(self) -> D {
        self.into_ctap().into_device()
    }

    fn ctap(&self) -> &ctap2::Ctap2<D> {
        self.ctap.as_ref().expect("Ctap2 already taken")
    }

    fn ctap_mut(&mut self) -> &mut ctap2::Ctap2<D> {
        self.ctap.as_mut().expect("Ctap2 already taken")
    }

    fn take_ctap(&mut self) -> ctap2::Ctap2<D> {
        self.ctap.take().expect("Ctap2 already taken")
    }

    fn restore_ctap(&mut self, ctap: ctap2::Ctap2<D>) {
        self.ctap = Some(ctap);
    }

    /// Create from a pre-existing Ctap2, for PyO3 per-call reconstruction.
    pub fn from_ctap(
        ctap: ctap2::Ctap2<D>,
        interaction: Box<dyn UserInteraction>,
        extensions: Vec<Box<dyn Ctap2Extension<D>>>,
        info: Info,
    ) -> Self {
        let mut c = ctap;
        c.set_info(info);
        Self {
            ctap: Some(c),
            extensions,
            interaction,
            enterprise_rpid_list: None,
        }
    }

    pub fn set_enterprise_rpid_list(&mut self, list: Option<Vec<String>>) {
        self.enterprise_rpid_list = list;
    }

    fn keepalive(&self) -> impl FnMut(u8) + '_ {
        |status| {
            if status == keepalive::UPNEEDED {
                self.interaction.prompt_up();
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn do_get_assertion_inner(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<
        (
            Vec<AssertionResponse>,
            Vec<Box<dyn AuthenticationExtensionProcessor<D>>>,
            Option<Vec<u8>>,
        ),
        ClientError,
    > {
        let info = self.ctap_mut().get_info()?;
        let pin_protocol = negotiate_pin_protocol(&info);

        let uv_requirement = options.user_verification.as_ref();
        let mut allow_uv = true;
        let mut user_verification = uv_requirement.cloned();

        loop {
            let mut used_extensions: Vec<Box<dyn AuthenticationExtensionProcessor<D>>> = Vec::new();
            let mut permissions = permission::GET_ASSERTION;

            let allow_cbor: Option<Vec<Value>> = options
                .allow_credentials
                .as_ref()
                .map(|creds| creds.iter().map(|d| d.to_cbor_value()).collect());

            let ctap = self.ctap.as_mut().expect("Ctap2 already taken");
            for ext_factory in &self.extensions {
                if let Some(proc) = ext_factory.get_assertion(
                    ctap,
                    options.extensions.as_ref(),
                    allow_cbor.as_deref(),
                    pin_protocol,
                ) {
                    permissions |= proc.permissions();
                    used_extensions.push(proc);
                }
            }

            let uv_str = user_verification.as_ref().map(|uv| uv.as_str());
            let ctap = self.take_ctap();
            let (ctap, pin_token, internal_uv) = get_auth_params(
                ctap,
                rp_id,
                uv_str,
                permissions,
                allow_uv,
                &mut self.keepalive(),
                self.interaction.as_ref(),
                pin_protocol.map(|p| p.version()),
            )?;
            self.restore_ctap(ctap);

            // Filter allow list
            let selected_cred = if let Some(ref allow_list) = options.allow_credentials {
                let allow_cbor: Vec<Value> = allow_list.iter().map(|d| d.to_cbor_value()).collect();
                let pin_auth_for_filter = pin_token.as_ref().and_then(|token| {
                    pin_protocol.map(|proto| proto.authenticate(token, &[0u8; 32]))
                });
                filter_creds(
                    self.ctap_mut(),
                    rp_id,
                    &allow_cbor,
                    pin_auth_for_filter.as_deref(),
                    pin_protocol.map(|p| p.version()),
                    &mut |_| {},
                )?
            } else {
                None
            };

            // Prepare extension inputs
            let mut extension_inputs = ExtensionInputs::new();
            for ext in &used_extensions {
                if let Some(inputs) =
                    ext.prepare_inputs(selected_cred.as_ref(), pin_token.as_deref())
                {
                    extension_inputs.extend(inputs);
                }
            }

            let opts = if internal_uv {
                Some(Value::Map(vec![(
                    Value::Text("uv".into()),
                    Value::Bool(true),
                )]))
            } else {
                None
            };

            let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
                if let Some(proto) = pin_protocol {
                    (
                        Some(proto.authenticate(token, client_data_hash)),
                        Some(proto.version()),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let allow_list_val = if let Some(ref cred) = selected_cred {
                Some(Value::Array(vec![cred.clone()]))
            } else if options.allow_credentials.is_some() {
                Some(Value::Array(vec![Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![0])),
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                ])]))
            } else {
                None
            };

            let extensions_val = if extension_inputs.is_empty() {
                None
            } else {
                Some(merge_extension_inputs(&extension_inputs))
            };

            let interaction = &*self.interaction;
            let mut on_keepalive = |status: u8| {
                if status == keepalive::UPNEEDED {
                    interaction.prompt_up();
                }
            };
            let ctap = self.ctap.as_mut().expect("Ctap2 already taken");
            match ctap.get_assertions(
                rp_id,
                client_data_hash,
                allow_list_val,
                extensions_val,
                opts,
                pin_uv_param.as_deref(),
                pin_uv_protocol,
                &mut on_keepalive,
                None,
            ) {
                Ok(assertions) => {
                    return Ok((assertions, used_extensions, pin_token));
                }
                Err(CtapError::StatusError(CtapStatus::PuatRequired))
                    if user_verification.as_ref().map(|uv| uv.as_str())
                        == Some(uv_requirement::DISCOURAGED) =>
                {
                    user_verification = Some(UserVerificationRequirement::Required);
                    continue;
                }
                Err(CtapError::StatusError(CtapStatus::UvBlocked)) if allow_uv => {
                    allow_uv = false;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl<D: CtapDevice> ClientBackend for Ctap2Backend<D> {
    fn info(&self) -> &Info {
        self.ctap().info()
    }

    fn selection(&mut self) -> Result<(), ClientError> {
        let ctap = self.ctap.as_mut().expect("Ctap2 already taken");
        let info = ctap.get_info()?;
        let interaction = &*self.interaction;
        let mut on_keepalive = |status: u8| {
            if status == keepalive::UPNEEDED {
                interaction.prompt_up();
            }
        };
        let ctap = self.ctap.as_mut().expect("Ctap2 already taken");
        if info.versions.iter().any(|v| v == "FIDO_2_1") {
            ctap.selection(&mut on_keepalive, None)
                .map_err(ClientError::from)
        } else {
            match ctap.make_credential(
                &[0u8; 32],
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Text("example.com".into())),
                    (
                        Value::Text("name".into()),
                        Value::Text("example.com".into()),
                    ),
                ]),
                Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(b"dummy".to_vec())),
                    (Value::Text("name".into()), Value::Text("dummy".into())),
                ]),
                Value::Array(vec![Value::Map(vec![
                    (Value::Text("type".into()), Value::Text("public-key".into())),
                    (Value::Text("alg".into()), Value::Int(-7)),
                ])]),
                None,
                None,
                None,
                Some(b""),
                None,
                None,
                &mut on_keepalive,
                None,
            ) {
                Ok(_) => Ok(()),
                Err(CtapError::StatusError(
                    CtapStatus::PinNotSet | CtapStatus::PinInvalid | CtapStatus::PinAuthInvalid,
                )) => Ok(()),
                Err(e) => Err(e.into()),
            }
        }
    }

    fn do_make_credential(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<(AttestationResponse, ExtensionOutputs), ClientError> {
        let info = self.ctap_mut().get_info()?;
        let pin_protocol = negotiate_pin_protocol(&info);

        let selection = options.authenticator_selection.as_ref();
        let uv_requirement = selection.and_then(|s| s.user_verification.as_ref());

        let enterprise_attestation =
            if options.attestation == Some(AttestationConveyancePreference::Enterprise) {
                if info.options.get("ep") == Some(&true) {
                    if let Some(ref list) = self.enterprise_rpid_list {
                        if list.iter().any(|id| id == rp_id) {
                            Some(2u32) // Platform-managed
                        } else {
                            Some(1u32) // Vendor-facilitated
                        }
                    } else {
                        Some(1u32) // Vendor-facilitated
                    }
                } else {
                    None
                }
            } else {
                None
            };

        let mut allow_uv = true;
        let mut user_verification = uv_requirement.cloned();

        loop {
            let mut used_extensions: Vec<Box<dyn RegistrationExtensionProcessor<D>>> = Vec::new();
            let mut permissions = permission::MAKE_CREDENTIAL;

            if options.exclude_credentials.is_some() {
                permissions |= permission::GET_ASSERTION;
            }

            {
                let ctap = self.ctap.as_mut().expect("Ctap2 already taken");
                for ext_factory in &self.extensions {
                    if let Some(proc) =
                        ext_factory.make_credential(ctap, options.extensions.as_ref(), pin_protocol)
                    {
                        permissions |= proc.permissions();
                        used_extensions.push(proc);
                    }
                }
            }

            let uv_str = user_verification.as_ref().map(|uv| uv.as_str());
            let ctap = self.take_ctap();
            let (ctap, pin_token, internal_uv) = get_auth_params(
                ctap,
                rp_id,
                uv_str,
                permissions,
                allow_uv,
                &mut self.keepalive(),
                self.interaction.as_ref(),
                pin_protocol.map(|p| p.version()),
            )?;
            self.restore_ctap(ctap);

            // Filter exclude list
            if let Some(ref exclude_list) = options.exclude_credentials {
                let exclude_cbor: Vec<Value> =
                    exclude_list.iter().map(|d| d.to_cbor_value()).collect();
                let pin_auth_for_filter = pin_token.as_ref().and_then(|token| {
                    pin_protocol.map(|proto| proto.authenticate(token, &[0u8; 32]))
                });
                let excluded = filter_creds(
                    self.ctap_mut(),
                    rp_id,
                    &exclude_cbor,
                    pin_auth_for_filter.as_deref(),
                    pin_protocol.map(|p| p.version()),
                    &mut |_| {},
                )?;
                if excluded.is_some() {
                    return Err(CtapError::StatusError(CtapStatus::CredentialExcluded).into());
                }
            }

            // Prepare extension inputs
            let mut extension_inputs = ExtensionInputs::new();
            for ext in &used_extensions {
                if let Some(inputs) = ext.prepare_inputs(pin_token.as_deref()) {
                    extension_inputs.extend(inputs);
                }
            }

            // Determine rk
            let rk_requirement = selection.and_then(|s| s.resident_key.as_ref());
            let can_rk = info.options.get("rk") == Some(&true);
            let rk = rk_requirement == Some(&ResidentKeyRequirement::Required)
                || (rk_requirement == Some(&ResidentKeyRequirement::Preferred) && can_rk);

            if rk && !can_rk {
                return Err(ClientError::ConfigurationUnsupported(
                    "Resident key not supported".into(),
                ));
            }

            let opts = if rk || internal_uv {
                let mut opts_map = Vec::new();
                if rk {
                    opts_map.push((Value::Text("rk".into()), Value::Bool(true)));
                }
                if internal_uv {
                    opts_map.push((Value::Text("uv".into()), Value::Bool(true)));
                }
                Some(Value::Map(opts_map))
            } else {
                None
            };

            let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
                if let Some(proto) = pin_protocol {
                    (
                        Some(proto.authenticate(token, client_data_hash)),
                        Some(proto.version()),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            let extensions_val = if extension_inputs.is_empty() {
                None
            } else {
                Some(merge_extension_inputs(&extension_inputs))
            };

            let interaction = &*self.interaction;
            let mut on_keepalive = |status: u8| {
                if status == keepalive::UPNEEDED {
                    interaction.prompt_up();
                }
            };
            let ctap = self.ctap.as_mut().expect("Ctap2 already taken");
            match ctap.make_credential(
                client_data_hash,
                options.rp.to_cbor_value(rp_id),
                options.user.to_cbor_value(),
                PublicKeyCredentialParameters::to_cbor_list(&options.pub_key_cred_params),
                None,
                extensions_val,
                opts,
                pin_uv_param.as_deref(),
                pin_uv_protocol,
                enterprise_attestation,
                &mut on_keepalive,
                None,
            ) {
                Ok(att_resp) => {
                    let mut extension_outputs = ExtensionOutputs::new();
                    for ext in &used_extensions {
                        if let Some(output) =
                            ext.prepare_outputs(&att_resp, pin_token.as_deref(), self.ctap_mut())
                        {
                            extension_outputs.extend(output);
                        }
                    }
                    return Ok((att_resp, extension_outputs));
                }
                Err(CtapError::StatusError(CtapStatus::PuatRequired))
                    if user_verification.as_ref().map(|uv| uv.as_str())
                        == Some(uv_requirement::DISCOURAGED) =>
                {
                    user_verification = Some(UserVerificationRequirement::Required);
                    continue;
                }
                Err(CtapError::StatusError(CtapStatus::UvBlocked)) if allow_uv => {
                    allow_uv = false;
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn do_get_assertion(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
        client_data_hash: &[u8],
        rp_id: &str,
    ) -> Result<(Vec<AssertionResponse>, Vec<ExtensionOutputs>), ClientError> {
        let (assertions, extensions, pin_token) =
            self.do_get_assertion_inner(options, client_data_hash, rp_id)?;

        let mut ext_outputs: Vec<ExtensionOutputs> = Vec::new();
        for assertion in &assertions {
            let mut outputs = ExtensionOutputs::new();
            for ext in &extensions {
                if let Some(ext_out) =
                    ext.prepare_outputs(assertion, pin_token.as_deref(), self.ctap_mut())
                {
                    outputs.extend(ext_out);
                }
            }
            ext_outputs.push(outputs);
        }

        Ok((assertions, ext_outputs))
    }
}

// ---------------------------------------------------------------------------
// Fido2Client
// ---------------------------------------------------------------------------

/// High-level FIDO2 WebAuthn client.
///
/// Automatically selects between CTAP1 (U2F) and CTAP2 backends based on
/// device capabilities. Falls back to CTAP1 if CTAP2 initialization fails.
pub struct Fido2Client {
    backend: Box<dyn ClientBackend>,
    collector: ClientDataCollector,
}

impl Fido2Client {
    /// Create a new Fido2Client.
    ///
    /// Tries CTAP2 first, then falls back to CTAP1 if the device doesn't
    /// support CBOR or if CTAP2 initialization fails.
    pub fn new<D: CtapDevice + 'static>(
        device: D,
        origin: &str,
        interaction: Box<dyn UserInteraction>,
        extensions: Vec<Box<dyn Ctap2Extension<D>>>,
    ) -> Result<Self, ClientError> {
        let backend: Box<dyn ClientBackend> = if device.capabilities() & capability::CBOR != 0 {
            match Ctap2Backend::new(device, interaction, extensions) {
                Ok(b) => Box::new(b),
                Err(_) => {
                    // Device consumed by failed Ctap2::new — can't fall back to CTAP1
                    return Err(ClientError::BadRequest(
                        "CTAP2 initialization failed".into(),
                    ));
                }
            }
        } else {
            Box::new(Ctap1Backend::new(device, interaction))
        };

        Ok(Self {
            backend,
            collector: ClientDataCollector::new(origin),
        })
    }

    /// Get authenticator information.
    pub fn info(&self) -> &Info {
        self.backend.info()
    }

    /// Perform authenticator selection (touch).
    pub fn selection(&mut self) -> Result<(), ClientError> {
        self.backend.selection()
    }

    /// Create a credential (WebAuthn registration).
    pub fn make_credential(
        &mut self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<RegistrationResponse, ClientError> {
        let rp_id = self.collector.get_rp_id(options.rp.id.as_deref())?;
        self.collector.verify_rp_id(&rp_id)?;

        let (client_data, _) = self
            .collector
            .collect_create(&options.challenge, Some(&rp_id))?;
        let client_data_hash = client_data.hash();

        let (attestation, extension_outputs) =
            self.backend
                .do_make_credential(options, &client_data_hash, &rp_id)?;

        let att_object = AttestationObject::create(
            &attestation.fmt,
            &attestation.auth_data,
            &attestation.att_stmt,
        );

        let credential_id = attestation
            .auth_data
            .credential_data
            .as_ref()
            .map(|cd| cd.credential_id.clone())
            .unwrap_or_default();

        let client_extension_results = if extension_outputs.is_empty() {
            None
        } else {
            cbor_map_to_json(&extension_outputs)
        };

        Ok(RegistrationResponse {
            id: websafe_encode(&credential_id),
            raw_id: credential_id,
            response: AuthenticatorAttestationResponse {
                client_data_json: client_data.as_bytes().to_vec(),
                attestation_object: att_object.as_bytes().to_vec(),
                transports: None,
            },
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            client_extension_results,
            type_: Some(PublicKeyCredentialType::PublicKey),
        })
    }

    /// Authenticate with a credential (WebAuthn authentication).
    pub fn get_assertion(
        &mut self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<AssertionSelection, ClientError> {
        let rp_id = self.collector.get_rp_id(options.rp_id.as_deref())?;
        self.collector.verify_rp_id(&rp_id)?;

        let (client_data, _) = self
            .collector
            .collect_get(&options.challenge, Some(&rp_id))?;
        let client_data_hash = client_data.hash();

        let (assertions, extension_outputs) =
            self.backend
                .do_get_assertion(options, &client_data_hash, &rp_id)?;

        Ok(AssertionSelection {
            client_data,
            assertions,
            extension_outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_rp_id_explicit() {
        let c = ClientDataCollector::new("https://example.com");
        assert_eq!(c.get_rp_id(Some("example.com")).unwrap(), "example.com");
    }

    #[test]
    fn test_get_rp_id_from_origin() {
        let c = ClientDataCollector::new("https://example.com");
        assert_eq!(c.get_rp_id(None).unwrap(), "example.com");
    }

    #[test]
    fn test_get_rp_id_http_requires_explicit() {
        let c = ClientDataCollector::new("http://example.com");
        assert!(c.get_rp_id(None).is_err());
    }

    #[test]
    fn test_verify_rp_id_valid() {
        let c = ClientDataCollector::new("https://example.com");
        assert!(c.verify_rp_id("example.com").is_ok());
    }

    #[test]
    fn test_verify_rp_id_invalid() {
        let c = ClientDataCollector::new("https://example.com");
        assert!(c.verify_rp_id("evil.com").is_err());
    }

    #[test]
    fn test_collect_create() {
        let c = ClientDataCollector::new("https://example.com");
        let (cd, rp_id) = c
            .collect_create(b"challenge_here__", Some("example.com"))
            .unwrap();
        assert_eq!(rp_id, "example.com");
        assert_eq!(cd.type_, "webauthn.create");
        assert_eq!(cd.origin, "https://example.com");
        assert_eq!(cd.challenge, b"challenge_here__");
    }

    #[test]
    fn test_collect_get() {
        let c = ClientDataCollector::new("https://example.com");
        let (cd, rp_id) = c.collect_get(b"challenge_here__", None).unwrap();
        assert_eq!(rp_id, "example.com");
        assert_eq!(cd.type_, "webauthn.get");
    }

    #[test]
    fn test_collect_bad_rp_id() {
        let c = ClientDataCollector::new("https://example.com");
        assert!(
            c.collect_create(b"challenge_here__", Some("evil.com"))
                .is_err()
        );
    }
}
