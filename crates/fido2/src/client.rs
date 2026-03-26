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

//! FIDO2 client helpers.
//!
//! Provides [`ClientDataCollector`] for constructing `CollectedClientData`
//! and validating RP IDs against origins.

use crate::cbor::Value;
use crate::ctap::{CtapDevice, CtapError, CtapStatus};
use crate::ctap2::{self, AttestationResponse, AssertionResponse, Info};
use crate::extensions::{
    AuthenticationExtensionProcessor, Ctap2Extension, ExtensionInputs, ExtensionOutputs,
};
use crate::pin::{ClientPin, PinProtocol};
use crate::server::verify_rp_id;
use crate::webauthn::{
    client_data_type, AttestationConveyancePreference, CollectedClientData,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, ResidentKeyRequirement, UserVerificationRequirement,
};

/// Errors returned by client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    ConfigurationUnsupported(String),
    #[error("PIN required but not provided")]
    PinRequired,
    #[error("CTAP error: {0}")]
    Ctap(#[from] CtapError),
}

/// User verification requirement values.
pub mod uv_requirement {
    pub const REQUIRED: &str = "required";
    pub const PREFERRED: &str = "preferred";
    pub const DISCOURAGED: &str = "discouraged";
}

/// ClientPin permission flags (mirrors Python ClientPin.PERMISSION).
pub mod permission {
    pub const MAKE_CREDENTIAL: u32 = 0x01;
    pub const GET_ASSERTION: u32 = 0x02;
}

/// Determine whether user verification should be performed.
///
/// This implements the UV decision logic from the FIDO2 client spec.
/// Returns `Ok(true)` if UV is needed, `Ok(false)` if not, or
/// `Err(ConfigurationUnsupported)` if UV is required but not configured.
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
    let additional_perms =
        permissions & !(permission::MAKE_CREDENTIAL | permission::GET_ASSERTION);

    if user_verification == Some(uv_requirement::REQUIRED)
        || (matches!(
            user_verification,
            Some(uv_requirement::PREFERRED) | None
        ) && uv_supported)
        || info.options.get("alwaysUv").copied().unwrap_or(false)
    {
        if !uv_configured {
            return Err(ClientError::ConfigurationUnsupported(
                "User verification not configured/supported".into(),
            ));
        }
        return Ok(true);
    } else if mc
        && uv_configured
        && !info.options.get("makeCredUvNotRqd").copied().unwrap_or(false)
    {
        return Ok(true);
    } else if uv_configured && additional_perms != 0 {
        return Ok(true);
    }
    Ok(false)
}

/// Filter a credential list against the authenticator.
///
/// Sends getAssertion with `up: false` to find which credentials exist.
/// Returns the matching credential (as a CBOR Value), or None if no match.
pub fn filter_creds(
    ctap: &ctap2::Ctap2,
    rp_id: &str,
    cred_list: &[Value],
    pin_auth: Option<&[u8]>,
    pin_version: Option<u32>,
    on_keepalive: &mut dyn FnMut(u8),
) -> Result<Option<Value>, CtapError> {
    // Get fresh info
    let info = ctap.get_info()?;

    // Filter out credential IDs which are too long
    let max_len = info.max_cred_id_length;
    let filtered: Vec<&Value> = if max_len > 0 {
        cred_list
            .iter()
            .filter(|c| {
                // Extract "id" from credential descriptor map
                if let Value::Map(entries) = c {
                    for (k, v) in entries {
                        if k.as_text() == Some("id") {
                            if let Some(id_bytes) = v.as_bytes() {
                                return id_bytes.len() <= max_len;
                            }
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

    // Options: {up: false}
    let options = Value::Map(vec![(
        Value::Text("up".to_string()),
        Value::Bool(false),
    )]);

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
        ) {
            Ok(assertion) => {
                if chunk.len() == 1 {
                    // Credential ID might be omitted from assertions
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

/// User interaction trait for PIN/UV token acquisition.
pub trait UserInteraction {
    fn request_pin(&self, permissions: u32, rp_id: Option<&str>) -> Option<String>;
    fn request_uv(&self, permissions: u32, rp_id: Option<&str>) -> bool;
}

/// Get a PIN/UV token from the authenticator.
///
/// Tries UV first (if allowed), then falls back to PIN.
/// Returns the token, or None if internal UV should be used (uv=True option).
pub fn get_token(
    info: &Info,
    client_pin: &ClientPin,
    permissions: u32,
    rp_id: Option<&str>,
    on_keepalive: &mut dyn FnMut(u8),
    allow_internal_uv: bool,
    allow_uv: bool,
    user_interaction: &dyn UserInteraction,
) -> Result<Option<Vec<u8>>, ClientError> {
    // Prefer UV
    if allow_uv && info.options.get("uv").copied().unwrap_or(false) {
        // Check if pinUvAuthToken is supported
        if info.options.get("pinUvAuthToken").copied() == Some(true) {
            if user_interaction.request_uv(permissions, rp_id) {
                let token = client_pin.get_uv_token(permissions, rp_id, on_keepalive)?;
                return Ok(Some(token));
            }
        } else if allow_internal_uv && user_interaction.request_uv(permissions, rp_id) {
            return Ok(None); // No token, use uv=True
        }
    }

    // PIN if UV not supported/allowed
    if info.options.get("clientPin").copied().unwrap_or(false) {
        if let Some(pin) = user_interaction.request_pin(permissions, rp_id) {
            if !pin.is_empty() {
                let token = client_pin.get_pin_token(&pin, Some(permissions), rp_id)?;
                return Ok(Some(token));
            }
        }
        return Err(ClientError::PinRequired);
    }

    Err(ClientError::ConfigurationUnsupported(
        "User verification not configured".into(),
    ))
}

/// Get auth parameters (pin_token, internal_uv) for a CTAP2 operation.
///
/// Combines `should_use_uv` and `get_token` logic.
/// Returns `(pin_token, internal_uv)`.
pub fn get_auth_params(
    ctap: &ctap2::Ctap2,
    rp_id: &str,
    user_verification: Option<&str>,
    permissions: u32,
    allow_uv: bool,
    on_keepalive: &mut dyn FnMut(u8),
    user_interaction: &dyn UserInteraction,
    pin_protocol_version: Option<u32>,
) -> Result<(Option<Vec<u8>>, bool), ClientError> {
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
        let client_pin = ClientPin::new(ctap, Some(protocol))?;

        let allow_internal_uv =
            permissions & !(permission::MAKE_CREDENTIAL | permission::GET_ASSERTION) == 0;

        let token = get_token(
            &info,
            &client_pin,
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
    }

    Ok((pin_token, internal_uv))
}

/// Collects client data and validates RP IDs for WebAuthn operations.
///
/// This is the Rust counterpart of `DefaultClientDataCollector` in Python.
pub struct ClientDataCollector {
    origin: String,
}

impl ClientDataCollector {
    /// Create a new collector for the given origin.
    pub fn new(origin: &str) -> Self {
        Self {
            origin: origin.to_string(),
        }
    }

    /// Get the origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Extract the effective RP ID from request parameters.
    ///
    /// If `rp_id` is `None`, falls back to the host component of the origin.
    /// Returns an error if the origin is not HTTPS or has no host.
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
                parsed
                    .host_str()
                    .map(|h| h.to_string())
                    .ok_or_else(|| {
                        ClientError::BadRequest(
                            "RP ID required for non-https origin.".into(),
                        )
                    })
            }
        }
    }

    /// Verify that an RP ID is valid for this collector's origin.
    pub fn verify_rp_id(&self, rp_id: &str) -> Result<(), ClientError> {
        if verify_rp_id(rp_id, &self.origin) {
            Ok(())
        } else {
            Err(ClientError::BadRequest(
                "RP ID not valid for origin.".into(),
            ))
        }
    }

    /// Collect client data for a registration (webauthn.create) request.
    ///
    /// Returns `(CollectedClientData, rp_id)`.
    pub fn collect_create(
        &self,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> Result<(CollectedClientData, String), ClientError> {
        let rp_id = self.get_rp_id(rp_id)?;
        self.verify_rp_id(&rp_id)?;
        let cd = CollectedClientData::create(
            client_data_type::CREATE,
            challenge,
            &self.origin,
            false,
        );
        Ok((cd, rp_id))
    }

    /// Collect client data for an authentication (webauthn.get) request.
    ///
    /// Returns `(CollectedClientData, rp_id)`.
    pub fn collect_get(
        &self,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> Result<(CollectedClientData, String), ClientError> {
        let rp_id = self.get_rp_id(rp_id)?;
        self.verify_rp_id(&rp_id)?;
        let cd = CollectedClientData::create(
            client_data_type::GET,
            challenge,
            &self.origin,
            false,
        );
        Ok((cd, rp_id))
    }
}

// ---------------------------------------------------------------------------
// Fido2Client — high-level WebAuthn client
// ---------------------------------------------------------------------------

/// Result of a make_credential operation.
pub struct RegistrationResult {
    /// The CTAP2 attestation response.
    pub attestation: AttestationResponse,
    /// The collected client data.
    pub client_data: CollectedClientData,
    /// Client extension outputs.
    pub extension_outputs: ExtensionOutputs,
}

/// Result of a get_assertion operation, wrapping one or more assertions.
///
/// Extension outputs are processed lazily per-assertion via [`get`].
pub struct AssertionSelection<'a> {
    ctap: &'a ctap2::Ctap2<'a>,
    /// The collected client data.
    pub client_data: CollectedClientData,
    assertions: Vec<AssertionResponse>,
    extensions: Vec<Box<dyn AuthenticationExtensionProcessor>>,
    pin_token: Option<Vec<u8>>,
}

impl<'a> AssertionSelection<'a> {
    /// Get the raw assertion responses.
    pub fn assertions(&self) -> &[AssertionResponse] {
        &self.assertions
    }

    /// Get the assertion at `index` with processed extension outputs.
    pub fn get(&self, index: usize) -> (&AssertionResponse, ExtensionOutputs) {
        let assertion = &self.assertions[index];
        let mut outputs = ExtensionOutputs::new();
        for ext in &self.extensions {
            if let Some(ext_out) =
                ext.prepare_outputs(assertion, self.pin_token.as_deref(), self.ctap)
            {
                outputs.extend(ext_out);
            }
        }
        (assertion, outputs)
    }
}

/// Negotiate the PIN/UV protocol version from authenticator info.
fn negotiate_pin_protocol(info: &Info) -> Option<PinProtocol> {
    // Prefer V2 over V1
    if info.pin_uv_protocols.contains(&2) {
        Some(PinProtocol::V2)
    } else if info.pin_uv_protocols.contains(&1) {
        Some(PinProtocol::V1)
    } else {
        None
    }
}

/// Merge extension inputs into a single CBOR Value (map of text keys).
fn merge_extension_inputs(inputs: &ExtensionInputs) -> Value {
    Value::Map(
        inputs
            .iter()
            .map(|(k, v)| (Value::Text(k.clone()), v.clone()))
            .collect(),
    )
}

/// High-level FIDO2 WebAuthn client.
///
/// Orchestrates extension processing, PIN/UV token acquisition, credential
/// filtering, and CTAP2 calls for registration and authentication.
pub struct Fido2Client<'a> {
    ctap: ctap2::Ctap2<'a>,
    collector: ClientDataCollector,
    interaction: &'a dyn UserInteraction,
    extensions: Vec<Box<dyn Ctap2Extension>>,
}

impl<'a> Fido2Client<'a> {
    /// Create a new Fido2Client.
    ///
    /// Initializes CTAP2 communication with the device and prepares
    /// client data collection for the given origin.
    pub fn new(
        device: &'a dyn CtapDevice,
        origin: &str,
        interaction: &'a dyn UserInteraction,
        extensions: Vec<Box<dyn Ctap2Extension>>,
    ) -> Result<Self, ClientError> {
        let ctap = ctap2::Ctap2::new(device, false)?;
        Ok(Self {
            ctap,
            collector: ClientDataCollector::new(origin),
            interaction,
            extensions,
        })
    }

    /// Get authenticator information.
    pub fn info(&self) -> &Info {
        self.ctap.info()
    }

    /// Create a credential (WebAuthn registration).
    pub fn make_credential(
        &self,
        options: &PublicKeyCredentialCreationOptions,
    ) -> Result<RegistrationResult, ClientError> {
        let rp_id = self
            .collector
            .get_rp_id(options.rp.id.as_deref())?;
        self.collector.verify_rp_id(&rp_id)?;

        let (client_data, _) = self.collector.collect_create(&options.challenge, Some(&rp_id))?;
        let client_data_hash = client_data.hash();

        let info = self.ctap.get_info()?;
        let pin_protocol = negotiate_pin_protocol(&info);

        // Determine user verification requirement
        let selection = options.authenticator_selection.as_ref();
        let uv_requirement = selection.and_then(|s| s.user_verification.as_ref());

        // Enterprise attestation
        let enterprise_attestation =
            if options.attestation == Some(AttestationConveyancePreference::Enterprise) {
                if info.options.get("ep") == Some(&true) {
                    Some(1u32) // Vendor facilitated
                } else {
                    None
                }
            } else {
                None
            };

        let mut allow_uv = true;
        let mut user_verification = uv_requirement.cloned();

        loop {
            // Initialize extensions and accumulate permissions
            let mut used_extensions: Vec<Box<dyn crate::extensions::RegistrationExtensionProcessor>> = Vec::new();
            let mut permissions = permission::MAKE_CREDENTIAL;

            if options.exclude_credentials.is_some() {
                permissions |= permission::GET_ASSERTION;
            }

            for ext_factory in &self.extensions {
                if let Some(proc) = ext_factory.make_credential(
                    &self.ctap,
                    options.extensions.as_ref(),
                    pin_protocol,
                ) {
                    permissions |= proc.permissions();
                    used_extensions.push(proc);
                }
            }

            // Get auth params
            let uv_str = user_verification.as_ref().map(|uv| uv.as_str());
            let (pin_token, internal_uv) = get_auth_params(
                &self.ctap,
                &rp_id,
                uv_str,
                permissions,
                allow_uv,
                &mut |status| {
                    if status == crate::ctap::keepalive::UPNEEDED {
                        self.interaction.request_uv(0, None);
                    }
                },
                self.interaction,
                pin_protocol.map(|p| p.version()),
            )?;

            // Filter exclude list
            if let Some(ref exclude_list) = options.exclude_credentials {
                let exclude_cbor: Vec<Value> =
                    exclude_list.iter().map(|d| d.to_cbor_value()).collect();
                let pin_auth_for_filter = pin_token.as_ref().and_then(|token| {
                    pin_protocol.map(|proto| proto.authenticate(token, &[0u8; 32]))
                });
                let _excluded = filter_creds(
                    &self.ctap,
                    &rp_id,
                    &exclude_cbor,
                    pin_auth_for_filter.as_deref(),
                    pin_protocol.map(|p| p.version()),
                    &mut |_| {},
                )?;
                // Note: even if excluded is Some, we don't fail early — the authenticator
                // needs to prompt for UP first
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

            // Build options map
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

            // Compute pin_auth
            let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
                if let Some(proto) = pin_protocol {
                    (
                        Some(proto.authenticate(token, &client_data_hash)),
                        Some(proto.version()),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // Call makeCredential
            let extensions_val = if extension_inputs.is_empty() {
                None
            } else {
                Some(merge_extension_inputs(&extension_inputs))
            };

            match self.ctap.make_credential(
                &client_data_hash,
                options.rp.to_cbor_value(&rp_id),
                options.user.to_cbor_value(),
                PublicKeyCredentialParameters::to_cbor_list(&options.pub_key_cred_params),
                None, // exclude_list is handled via filter_creds above
                extensions_val,
                opts,
                pin_uv_param.as_deref(),
                pin_uv_protocol,
                enterprise_attestation,
                &mut |status| {
                    if status == crate::ctap::keepalive::UPNEEDED {
                        self.interaction.request_uv(0, None);
                    }
                },
            ) {
                Ok(att_resp) => {
                    // Process extension outputs
                    let mut extension_outputs = ExtensionOutputs::new();
                    for ext in &used_extensions {
                        if let Some(output) =
                            ext.prepare_outputs(&att_resp, pin_token.as_deref(), &self.ctap)
                        {
                            extension_outputs.extend(output);
                        }
                    }

                    return Ok(RegistrationResult {
                        attestation: att_resp,
                        client_data,
                        extension_outputs,
                    });
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

    /// Authenticate with a credential (WebAuthn authentication).
    pub fn get_assertion(
        &'a self,
        options: &PublicKeyCredentialRequestOptions,
    ) -> Result<AssertionSelection<'a>, ClientError> {
        let rp_id = self.collector.get_rp_id(options.rp_id.as_deref())?;
        self.collector.verify_rp_id(&rp_id)?;

        let (client_data, _) = self.collector.collect_get(&options.challenge, Some(&rp_id))?;
        let client_data_hash = client_data.hash();

        let info = self.ctap.get_info()?;
        let pin_protocol = negotiate_pin_protocol(&info);

        let uv_requirement = options.user_verification.as_ref();
        let mut allow_uv = true;
        let mut user_verification = uv_requirement.cloned();

        loop {
            // Initialize extensions and accumulate permissions
            let mut used_extensions: Vec<Box<dyn AuthenticationExtensionProcessor>> = Vec::new();
            let mut permissions = permission::GET_ASSERTION;

            let allow_cbor: Option<Vec<Value>> = options
                .allow_credentials
                .as_ref()
                .map(|creds| creds.iter().map(|d| d.to_cbor_value()).collect());

            for ext_factory in &self.extensions {
                if let Some(proc) = ext_factory.get_assertion(
                    &self.ctap,
                    options.extensions.as_ref(),
                    allow_cbor.as_deref(),
                    pin_protocol,
                ) {
                    permissions |= proc.permissions();
                    used_extensions.push(proc);
                }
            }

            // Get auth params
            let uv_str = user_verification.as_ref().map(|uv| uv.as_str());
            let (pin_token, internal_uv) = get_auth_params(
                &self.ctap,
                &rp_id,
                uv_str,
                permissions,
                allow_uv,
                &mut |status| {
                    if status == crate::ctap::keepalive::UPNEEDED {
                        self.interaction.request_uv(0, None);
                    }
                },
                self.interaction,
                pin_protocol.map(|p| p.version()),
            )?;

            // Filter allow list
            let selected_cred = if let Some(ref allow_list) = options.allow_credentials {
                let allow_cbor: Vec<Value> =
                    allow_list.iter().map(|d| d.to_cbor_value()).collect();
                let pin_auth_for_filter = pin_token.as_ref().and_then(|token| {
                    pin_protocol.map(|proto| proto.authenticate(token, &[0u8; 32]))
                });
                filter_creds(
                    &self.ctap,
                    &rp_id,
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

            // Compute pin_auth
            let (pin_uv_param, pin_uv_protocol) = if let Some(ref token) = pin_token {
                if let Some(proto) = pin_protocol {
                    (
                        Some(proto.authenticate(token, &client_data_hash)),
                        Some(proto.version()),
                    )
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

            // Build allow list for CTAP2 call
            let allow_list_val = if let Some(ref cred) = selected_cred {
                Some(Value::Array(vec![cred.clone()]))
            } else if options.allow_credentials.is_some() {
                // Allow list existed but no match — send dummy
                Some(Value::Array(vec![Value::Map(vec![
                    (Value::Text("id".into()), Value::Bytes(vec![0])),
                    (
                        Value::Text("type".into()),
                        Value::Text("public-key".into()),
                    ),
                ])]))
            } else {
                None
            };

            let extensions_val = if extension_inputs.is_empty() {
                None
            } else {
                Some(merge_extension_inputs(&extension_inputs))
            };

            match self.ctap.get_assertions(
                &rp_id,
                &client_data_hash,
                allow_list_val,
                extensions_val,
                opts,
                pin_uv_param.as_deref(),
                pin_uv_protocol,
                &mut |status| {
                    if status == crate::ctap::keepalive::UPNEEDED {
                        self.interaction.request_uv(0, None);
                    }
                },
            ) {
                Ok(assertions) => {
                    return Ok(AssertionSelection {
                        ctap: &self.ctap,
                        client_data,
                        assertions,
                        extensions: used_extensions,
                        pin_token,
                    });
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
        let (cd, rp_id) = c.collect_create(b"challenge_here__", Some("example.com")).unwrap();
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
        assert!(c.collect_create(b"challenge_here__", Some("evil.com")).is_err());
    }
}
