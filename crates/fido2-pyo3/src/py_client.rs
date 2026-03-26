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

use fido2::cbor::Value;
use fido2::client;
use fido2::ctap2;
use fido2::pin::PinProtocol;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::py_ctap::PyCtapDevice;

/// Native client data collector.
///
/// Handles RP ID resolution, origin validation, and CollectedClientData creation.
/// Supports an optional custom `verify` callback `(rp_id: str, origin: str) -> bool`.
#[pyclass]
struct ClientDataCollector {
    inner: client::ClientDataCollector,
    verify: Option<PyObject>,
}

impl ClientDataCollector {
    /// Verify RP ID using custom callback or default.
    fn check_rp_id(&self, py: Python<'_>, rp_id: &str) -> PyResult<()> {
        match &self.verify {
            Some(cb) => {
                let valid = cb
                    .call1(py, (rp_id, self.inner.origin()))?
                    .extract::<bool>(py)?;
                if !valid {
                    return Err(PyValueError::new_err("RP ID not valid for origin."));
                }
                Ok(())
            }
            None => self
                .inner
                .verify_rp_id(rp_id)
                .map_err(|e| PyValueError::new_err(e.to_string())),
        }
    }
}

#[pymethods]
impl ClientDataCollector {
    #[new]
    #[pyo3(signature = (origin, verify=None))]
    fn new(origin: &str, verify: Option<PyObject>) -> Self {
        Self {
            inner: client::ClientDataCollector::new(origin),
            verify,
        }
    }

    /// Get the origin.
    #[getter]
    fn origin(&self) -> &str {
        self.inner.origin()
    }

    /// Extract the effective RP ID from request parameters.
    ///
    /// If `rp_id` is None, falls back to the host from the origin.
    #[pyo3(signature = (rp_id=None))]
    fn get_rp_id(&self, rp_id: Option<&str>) -> PyResult<String> {
        self.inner
            .get_rp_id(rp_id)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Verify that an RP ID is valid for this collector's origin.
    fn verify_rp_id_py(&self, py: Python<'_>, rp_id: &str) -> PyResult<()> {
        self.check_rp_id(py, rp_id)
    }

    /// Collect client data for a request.
    ///
    /// `type_` should be "webauthn.create" or "webauthn.get".
    /// Returns `(client_data_json_bytes, rp_id)`.
    #[pyo3(signature = (type_, challenge, rp_id=None))]
    fn collect_client_data<'py>(
        &self,
        py: Python<'py>,
        type_: &str,
        challenge: &[u8],
        rp_id: Option<&str>,
    ) -> PyResult<(Bound<'py, PyBytes>, String)> {
        let rp_id = self
            .inner
            .get_rp_id(rp_id)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.check_rp_id(py, &rp_id)?;

        let cd = fido2::webauthn::CollectedClientData::create(
            type_,
            challenge,
            self.inner.origin(),
            false,
        );
        let bytes = PyBytes::new(py, cd.as_bytes());
        Ok((bytes, rp_id))
    }
}

// ---- Error conversion helpers ----

fn client_err(e: client::ClientError) -> PyErr {
    match e {
        client::ClientError::BadRequest(msg) => {
            PyValueError::new_err(format!("CLIENT_BAD_REQUEST:{}", msg))
        }
        client::ClientError::ConfigurationUnsupported(msg) => {
            PyValueError::new_err(format!("CLIENT_CONFIG_UNSUPPORTED:{}", msg))
        }
        client::ClientError::PinRequired => {
            PyValueError::new_err("CLIENT_PIN_REQUIRED".to_string())
        }
        client::ClientError::Ctap(e) => crate::py_ctap::ctap_err(e),
    }
}

// ---- UserInteraction bridge ----

/// Bridges a Python UserInteraction object to the Rust UserInteraction trait.
struct PyUserInteraction {
    py_obj: PyObject,
    permissions: u32,
    rp_id: Option<String>,
}

impl client::UserInteraction for PyUserInteraction {
    fn request_pin(&self, _permissions: u32, _rp_id: Option<&str>) -> Option<String> {
        Python::with_gil(|py| {
            let rp_id = self
                .rp_id
                .as_ref()
                .map_or_else(|| py.None(), |s| s.clone().into_pyobject(py).unwrap().into_any().unbind());
            self.py_obj
                .call_method1(py, "request_pin", (self.permissions, rp_id))
                .ok()
                .and_then(|result| result.extract::<Option<String>>(py).ok().flatten())
        })
    }

    fn request_uv(&self, _permissions: u32, _rp_id: Option<&str>) -> bool {
        Python::with_gil(|py| {
            let rp_id = self
                .rp_id
                .as_ref()
                .map_or_else(|| py.None(), |s| s.clone().into_pyobject(py).unwrap().into_any().unbind());
            self.py_obj
                .call_method1(py, "request_uv", (self.permissions, rp_id))
                .ok()
                .and_then(|result| result.extract::<bool>(py).ok())
                .unwrap_or(false)
        })
    }
}

// ---- NativeCtap2ClientBackend ----

#[pyclass]
struct NativeCtap2ClientBackend {
    device: PyObject,
    strict_cbor: bool,
    max_msg_size: usize,
}

#[pymethods]
impl NativeCtap2ClientBackend {
    #[new]
    fn new(device: PyObject, strict_cbor: bool, max_msg_size: usize) -> Self {
        Self {
            device,
            strict_cbor,
            max_msg_size,
        }
    }

    /// Filter credential list against the authenticator.
    ///
    /// Returns the matching credential descriptor (as a Python dict), or None.
    #[pyo3(signature = (rp_id, cred_list, pin_version, pin_token, event=None, on_keepalive=None))]
    fn filter_creds(
        &self,
        py: Python<'_>,
        rp_id: &str,
        cred_list: Vec<PyObject>,
        pin_version: Option<u32>,
        pin_token: Option<&[u8]>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Option<PyObject>> {
        // Convert Python credential descriptors to CBOR Values
        let values: Vec<Value> = cred_list
            .into_iter()
            .map(|obj| crate::py_ctap::py_to_val(py, obj))
            .collect::<PyResult<Vec<_>>>()?;

        // Compute pin_auth if we have a token
        let pin_auth = match (pin_token, pin_version) {
            (Some(token), Some(version)) => {
                let protocol = match version {
                    1 => PinProtocol::V1,
                    2 => PinProtocol::V2,
                    _ => return Err(PyValueError::new_err("Unsupported protocol version")),
                };
                let client_data_hash = [0u8; 32];
                Some(protocol.authenticate(token, &client_data_hash))
            }
            _ => None,
        };

        let dev = PyCtapDevice::with_event(
            py,
            self.device.clone_ref(py),
            event,
            on_keepalive,
        )?;
        let ctap = ctap2::Ctap2::from_parts(&dev, self.strict_cbor, self.max_msg_size);

        let result = client::filter_creds(
            &ctap,
            rp_id,
            &values,
            pin_auth.as_deref(),
            pin_version,
            &mut |_| {},
        )
        .map_err(crate::py_ctap::ctap_err)?;

        match result {
            Some(val) => Ok(Some(crate::py_ctap::val_to_pyobj(py, &val)?)),
            None => Ok(None),
        }
    }

    /// Get auth parameters (pin_token, internal_uv) for a CTAP2 operation.
    ///
    /// Returns (pin_token: Optional[bytes], internal_uv: bool).
    #[pyo3(signature = (rp_id, user_verification, permissions, pin_version, allow_uv, event=None, on_keepalive=None, user_interaction=None))]
    fn get_auth_params<'py>(
        &self,
        py: Python<'py>,
        rp_id: &str,
        user_verification: Option<&str>,
        permissions: u32,
        pin_version: Option<u32>,
        allow_uv: bool,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
        user_interaction: Option<PyObject>,
    ) -> PyResult<(Option<Bound<'py, PyBytes>>, bool)> {
        let dev = PyCtapDevice::with_event(
            py,
            self.device.clone_ref(py),
            event,
            on_keepalive,
        )?;
        let ctap = ctap2::Ctap2::from_parts(&dev, self.strict_cbor, self.max_msg_size);

        let ui = user_interaction
            .ok_or_else(|| PyValueError::new_err("user_interaction is required"))?;

        let py_ui = PyUserInteraction {
            py_obj: ui,
            permissions,
            rp_id: Some(rp_id.to_string()),
        };

        let (pin_token, internal_uv) = client::get_auth_params(
            &ctap,
            rp_id,
            user_verification,
            permissions,
            allow_uv,
            &mut |_| {},
            &py_ui,
            pin_version,
        )
        .map_err(client_err)?;

        let py_token = pin_token.map(|t| PyBytes::new(py, &t));
        Ok((py_token, internal_uv))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "client")?;
    sub.add_class::<ClientDataCollector>()?;
    sub.add_class::<NativeCtap2ClientBackend>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.client", &sub)?;

    Ok(())
}
