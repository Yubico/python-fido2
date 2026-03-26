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

use fido2::webauthn::{AttestedCredentialData, AttestationObject, AuthenticatorData, CollectedClientData};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::py_cbor::value_to_py;

/// Parse AttestedCredentialData from binary data.
///
/// Returns (aaguid, credential_id, public_key_dict, remaining_bytes).
#[pyfunction]
fn parse_credential_data<'py>(
    py: Python<'py>,
    data: &[u8],
) -> PyResult<(
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    PyObject,
    Bound<'py, PyBytes>,
)> {
    let (cred_data, rest) =
        AttestedCredentialData::from_bytes(data).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let aaguid = PyBytes::new(py, cred_data.aaguid.as_bytes());
    let credential_id = PyBytes::new(py, &cred_data.credential_id);
    let public_key = value_to_py(py, &cred_data.public_key.to_cbor())?.into();
    let remaining = PyBytes::new(py, rest);

    Ok((aaguid, credential_id, public_key, remaining))
}

/// Parse AttestationObject from CBOR-encoded bytes.
///
/// Returns (fmt, auth_data_bytes, att_stmt_dict).
#[pyfunction]
fn parse_attestation_object<'py>(
    py: Python<'py>,
    data: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>, PyObject)> {
    let att_obj =
        AttestationObject::from_bytes(data).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let auth_data = PyBytes::new(py, att_obj.auth_data.as_bytes());
    let att_stmt = value_to_py(py, &att_obj.att_stmt)?.into();

    Ok((att_obj.fmt, auth_data, att_stmt))
}

/// Parse CollectedClientData from JSON-encoded bytes.
///
/// Returns (type, challenge, origin, cross_origin).
#[pyfunction]
fn parse_collected_client_data<'py>(
    py: Python<'py>,
    data: &[u8],
) -> PyResult<(String, Bound<'py, PyBytes>, String, bool)> {
    let cd = CollectedClientData::from_bytes(data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let challenge = PyBytes::new(py, &cd.challenge);
    Ok((cd.type_, challenge, cd.origin, cd.cross_origin))
}

/// Parse AuthenticatorData from binary data.
///
/// Returns (rp_id_hash, flags, counter, credential_data_bytes, extensions).
#[pyfunction]
fn parse_authenticator_data<'py>(
    py: Python<'py>,
    data: &[u8],
) -> PyResult<(
    Bound<'py, PyBytes>,
    u8,
    u32,
    Option<Bound<'py, PyBytes>>,
    Option<PyObject>,
)> {
    let auth_data =
        AuthenticatorData::from_bytes(data).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let rp_id_hash = PyBytes::new(py, &auth_data.rp_id_hash);
    let flags = auth_data.flags.bits();
    let counter = auth_data.counter;

    let credential_data = auth_data
        .credential_data
        .as_ref()
        .map(|cd| PyBytes::new(py, cd.as_bytes()));

    let extensions = auth_data
        .extensions
        .as_ref()
        .map(|ext| value_to_py(py, ext).map(|v| v.into()))
        .transpose()?;

    Ok((rp_id_hash, flags, counter, credential_data, extensions))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "webauthn")?;
    sub.add_function(wrap_pyfunction!(parse_credential_data, &sub)?)?;
    sub.add_function(wrap_pyfunction!(parse_attestation_object, &sub)?)?;
    sub.add_function(wrap_pyfunction!(parse_collected_client_data, &sub)?)?;
    sub.add_function(wrap_pyfunction!(parse_authenticator_data, &sub)?)?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.webauthn", &sub)?;

    Ok(())
}
