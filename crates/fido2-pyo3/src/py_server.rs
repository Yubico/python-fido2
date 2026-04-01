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

use fido2_server::cbor;
use fido2_server::cose::CoseKey;
use fido2_server::server;
use fido2_server::webauthn::{
    AttestationObject, AuthenticatorData, CollectedClientData, PublicKeyCredentialRpEntity,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

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

    server::verify_registration(
        &cd,
        &att_obj,
        challenge,
        rp_id_hash,
        user_verification_required,
    )
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

/// Native FIDO2 server wrapping the Rust Fido2Server.
///
/// Supports optional Python callbacks for origin and attestation verification.
#[pyclass]
struct Fido2Server {
    inner: server::Fido2Server,
    verify_origin: Option<PyObject>,
    verify_attestation: Option<PyObject>,
    attestation: Option<String>,
}

impl Fido2Server {
    /// Check origin using custom callback or default RP ID verification.
    fn check_origin(&self, py: Python<'_>, origin: &str) -> PyResult<()> {
        let valid = match &self.verify_origin {
            Some(cb) => cb.call1(py, (origin,))?.extract::<bool>(py)?,
            None => self.inner.verify_origin(origin),
        };
        if !valid {
            return Err(PyValueError::new_err(
                "Invalid origin in CollectedClientData.",
            ));
        }
        Ok(())
    }

    /// Check attestation using custom callback if attestation is required.
    fn check_attestation(
        &self,
        py: Python<'_>,
        attestation_object: &[u8],
        client_data_hash: &[u8],
    ) -> PyResult<()> {
        let dominated = matches!(self.attestation.as_deref(), None | Some("none"));
        if dominated {
            return Ok(());
        }
        if let Some(cb) = &self.verify_attestation {
            let att_bytes = PyBytes::new(py, attestation_object);
            let cdh_bytes = PyBytes::new(py, client_data_hash);
            cb.call1(py, (att_bytes, cdh_bytes))?;
        }
        Ok(())
    }

    fn make_state(challenge: &[u8], user_verification_required: bool) -> server::ServerState {
        server::ServerState {
            challenge: challenge.to_vec(),
            user_verification: if user_verification_required {
                Some(fido2_server::webauthn::UserVerificationRequirement::Required)
            } else {
                None
            },
        }
    }
}

#[pymethods]
impl Fido2Server {
    #[new]
    #[pyo3(signature = (rp_id, rp_name, attestation=None, verify_origin=None, verify_attestation=None))]
    fn new(
        rp_id: &str,
        rp_name: &str,
        attestation: Option<String>,
        verify_origin: Option<PyObject>,
        verify_attestation: Option<PyObject>,
    ) -> PyResult<Self> {
        let rp = PublicKeyCredentialRpEntity {
            name: rp_name.into(),
            id: Some(rp_id.into()),
        };
        let inner =
            server::Fido2Server::new(rp, None).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self {
            inner,
            verify_origin,
            verify_attestation,
            attestation,
        })
    }

    /// Check if an origin is valid for this server's RP ID.
    ///
    /// Uses custom verify_origin callback if set, otherwise the default.
    fn check_origin_py(&self, py: Python<'_>, origin: &str) -> PyResult<bool> {
        match &self.verify_origin {
            Some(cb) => cb.call1(py, (origin,))?.extract::<bool>(py),
            None => Ok(self.inner.verify_origin(origin)),
        }
    }

    /// SHA-256 hash of the RP ID.
    #[getter]
    fn rp_id_hash<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.rp_id_hash())
    }

    /// List of supported COSE algorithm identifiers.
    #[getter]
    fn allowed_algorithms(&self) -> Vec<i64> {
        self.inner
            .allowed_algorithms
            .iter()
            .map(|p| p.alg)
            .collect()
    }

    /// Generate a random challenge or validate a provided one.
    ///
    /// Returns the challenge bytes.
    #[pyo3(signature = (challenge=None))]
    fn generate_challenge<'py>(
        &self,
        py: Python<'py>,
        challenge: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let challenge = server::generate_or_validate_challenge(challenge)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &challenge))
    }

    /// Complete a registration ceremony.
    ///
    /// Verifies origin, client data, attestation object, and optionally
    /// attestation statement via the verify_attestation callback.
    fn register_complete(
        &self,
        py: Python<'_>,
        client_data: &[u8],
        attestation_object: &[u8],
        challenge: &[u8],
        user_verification_required: bool,
    ) -> PyResult<()> {
        let cd = CollectedClientData::from_bytes(client_data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let att_obj = AttestationObject::from_bytes(attestation_object)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        self.check_origin(py, &cd.origin)?;

        let state = Self::make_state(challenge, user_verification_required);
        self.inner
            .register_complete(&state, &cd, &att_obj)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        self.check_attestation(py, attestation_object, &cd.hash())?;

        Ok(())
    }

    /// Complete an authentication ceremony.
    ///
    /// Verifies origin, client data, authenticator data, and signature.
    /// `credentials` is a list of (credential_id: bytes, public_key_cbor: bytes) tuples.
    /// Returns the index of the matched credential.
    #[allow(clippy::too_many_arguments)]
    fn authenticate_complete(
        &self,
        py: Python<'_>,
        client_data: &[u8],
        auth_data: &[u8],
        challenge: &[u8],
        user_verification_required: bool,
        credentials: Vec<(Vec<u8>, Vec<u8>)>,
        credential_id: &[u8],
        signature: &[u8],
    ) -> PyResult<usize> {
        let cd = CollectedClientData::from_bytes(client_data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let ad = AuthenticatorData::from_bytes(auth_data)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        self.check_origin(py, &cd.origin)?;

        let creds: Vec<(Vec<u8>, CoseKey)> = credentials
            .into_iter()
            .map(|(id, pk)| {
                let value = cbor::decode(&pk).map_err(|e| PyValueError::new_err(e.to_string()))?;
                let key =
                    CoseKey::from_cbor(&value).map_err(|e| PyValueError::new_err(e.to_string()))?;
                Ok((id, key))
            })
            .collect::<PyResult<_>>()?;

        let state = Self::make_state(challenge, user_verification_required);

        self.inner
            .authenticate_complete(&state, &creds, credential_id, &cd, &ad, signature)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "server")?;
    sub.add_function(wrap_pyfunction!(verify_rp_id, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_registration, &sub)?)?;
    sub.add_function(wrap_pyfunction!(verify_authentication, &sub)?)?;
    sub.add_class::<Fido2Server>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.server", &sub)?;

    Ok(())
}
