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

use fido2::server;
use fido2::webauthn::{AttestationObject, AuthenticatorData, CollectedClientData};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Check if an RP ID is valid for a given origin.
#[pyfunction]
fn verify_rp_id(rp_id: &str, origin: &str) -> bool {
    server::verify_rp_id(rp_id, origin)
}

/// Verify a registration (webauthn.create) response.
///
/// Raises ValueError if verification fails.
#[pyfunction]
fn verify_registration(
    client_data: &[u8],
    attestation_object: &[u8],
    challenge: &[u8],
    rp_id_hash: &[u8],
    user_verification_required: bool,
) -> PyResult<()> {
    let cd = CollectedClientData::from_bytes(client_data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let att_obj = AttestationObject::from_bytes(attestation_object)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    server::verify_registration(&cd, &att_obj, challenge, rp_id_hash, user_verification_required)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Verify an authentication (webauthn.get) response.
///
/// Raises ValueError if verification fails.
#[pyfunction]
fn verify_authentication(
    client_data: &[u8],
    auth_data: &[u8],
    challenge: &[u8],
    rp_id_hash: &[u8],
    user_verification_required: bool,
) -> PyResult<()> {
    let cd = CollectedClientData::from_bytes(client_data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ad = AuthenticatorData::from_bytes(auth_data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    server::verify_authentication(&cd, &ad, challenge, rp_id_hash, user_verification_required)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "server")?;
    sub.add_function(wrap_pyfunction!(verify_rp_id, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_registration, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_authentication, &sub)?)?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.server", &sub)?;

    Ok(())
}
