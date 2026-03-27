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

use fido2::client::{self, ClientBackend};
use fido2::ctap::capability;
use fido2::ctap2::{self, Info};
use fido2::extensions::default_extensions;
use fido2::webauthn::Aaguid;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

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
        client::ClientError::DeviceIneligible => {
            PyValueError::new_err("CLIENT_DEVICE_INELIGIBLE".to_string())
        }
        client::ClientError::Timeout => {
            PyValueError::new_err("CLIENT_TIMEOUT".to_string())
        }
        client::ClientError::Ctap(e) => crate::py_ctap::ctap_err(e),
    }
}

// ---- UserInteraction bridge ----

/// Bridges a Python UserInteraction object to the Rust UserInteraction trait.
///
/// Forwards the trait's `permissions` and `rp_id` parameters directly to the
/// Python object's methods.
struct PyUserInteraction {
    py_obj: PyObject,
}

impl client::UserInteraction for PyUserInteraction {
    fn prompt_up(&self) {
        Python::with_gil(|py| {
            let _ = self.py_obj.call_method0(py, "prompt_up");
        });
    }

    fn request_pin(&self, permissions: u32, rp_id: Option<&str>) -> Option<String> {
        Python::with_gil(|py| {
            let rp_id_py = rp_id.map_or_else(
                || py.None(),
                |s| s.into_pyobject(py).unwrap().into_any().unbind(),
            );
            self.py_obj
                .call_method1(py, "request_pin", (permissions, rp_id_py))
                .ok()
                .and_then(|result| result.extract::<Option<String>>(py).ok().flatten())
        })
    }

    fn request_uv(&self, permissions: u32, rp_id: Option<&str>) -> bool {
        Python::with_gil(|py| {
            let rp_id_py = rp_id.map_or_else(
                || py.None(),
                |s| s.into_pyobject(py).unwrap().into_any().unbind(),
            );
            self.py_obj
                .call_method1(py, "request_uv", (permissions, rp_id_py))
                .ok()
                .and_then(|result| result.extract::<bool>(py).ok())
                .unwrap_or(false)
        })
    }
}

// ---- NativeFido2Client ----

/// Native FIDO2 client handling both CTAP1 and CTAP2 backends.
///
/// At construction, probes the device to determine capabilities and caches
/// authenticator info. Per-call, creates temporary backend objects to perform
/// operations.
#[pyclass]
struct NativeFido2Client {
    device: PyObject,
    user_interaction: PyObject,
    on_keepalive: PyObject,
    info: Info,
    is_ctap2: bool,
    allow_hmac_secret: bool,
}

impl NativeFido2Client {
    /// Create a PyCtapDevice for a call, using the stored device and on_keepalive.
    fn make_device(&self, py: Python<'_>, event: Option<PyObject>) -> PyResult<PyCtapDevice> {
        PyCtapDevice::with_event(
            py,
            self.device.clone_ref(py),
            event,
            Some(self.on_keepalive.clone_ref(py)),
        )
    }

    /// Create a PyUserInteraction from the stored user_interaction.
    fn make_interaction(&self) -> PyUserInteraction {
        PyUserInteraction {
            py_obj: Python::with_gil(|py| self.user_interaction.clone_ref(py)),
        }
    }

    /// Create the appropriate backend based on cached capabilities.
    fn make_backend<'a>(
        &self,
        dev: &'a PyCtapDevice,
        ui: &'a PyUserInteraction,
    ) -> Box<dyn ClientBackend + 'a> {
        if self.is_ctap2 {
            Box::new(client::Ctap2Backend::from_parts(
                dev,
                false,
                self.info.max_msg_size,
                ui,
                default_extensions(self.allow_hmac_secret),
                self.info.clone(),
            ))
        } else {
            Box::new(client::Ctap1Backend::new(dev, ui))
        }
    }
}

#[pymethods]
impl NativeFido2Client {
    #[new]
    #[pyo3(signature = (device, user_interaction, on_keepalive, allow_hmac_secret=false))]
    fn new(
        py: Python<'_>,
        device: PyObject,
        user_interaction: PyObject,
        on_keepalive: PyObject,
        allow_hmac_secret: bool,
    ) -> PyResult<Self> {
        let capabilities: u8 = device.getattr(py, "capabilities")?.extract(py)?;
        let is_ctap2 = capabilities & capability::CBOR != 0;

        let info = if is_ctap2 {
            let dev = PyCtapDevice::new(py, device.clone_ref(py))?;
            match ctap2::Ctap2::new(&dev, false) {
                Ok(ctap) => ctap.info().clone(),
                Err(e) => return Err(crate::py_ctap::ctap_err(e)),
            }
        } else {
            Info {
                versions: vec!["U2F_V2".into()],
                aaguid: Aaguid::NONE,
                ..Info::from_cbor(&[])
            }
        };

        Ok(Self {
            device,
            user_interaction,
            on_keepalive,
            info,
            is_ctap2,
            allow_hmac_secret,
        })
    }

    /// Get cached authenticator info as a Python dict.
    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<PyObject> {
        crate::py_ctap::info_to_py(py, &self.info)
    }

    /// Perform authenticator selection (touch).
    #[pyo3(signature = (event=None))]
    fn selection(&self, py: Python<'_>, event: Option<PyObject>) -> PyResult<()> {
        let dev = self.make_device(py, event)?;
        let ui = self.make_interaction();
        let backend = self.make_backend(&dev, &ui);
        backend.selection().map_err(client_err)
    }

    /// Perform the full make_credential operation.
    ///
    /// Takes JSON-serialized options, pre-computed client_data_hash and rp_id.
    /// Returns (attestation_response_dict, extension_outputs_dict).
    #[pyo3(signature = (options_json, client_data_hash, rp_id, event=None))]
    fn do_make_credential(
        &self,
        py: Python<'_>,
        options_json: &str,
        client_data_hash: &[u8],
        rp_id: &str,
        event: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let options: fido2::webauthn::PublicKeyCredentialCreationOptions =
            serde_json::from_str(options_json)
                .map_err(|e| PyValueError::new_err(format!("Invalid options JSON: {}", e)))?;

        let dev = self.make_device(py, event)?;
        let ui = self.make_interaction();
        let backend = self.make_backend(&dev, &ui);

        let (att_resp, ext_outputs) = backend
            .do_make_credential(&options, client_data_hash, rp_id)
            .map_err(client_err)?;

        let att_dict = crate::py_ctap::attestation_response_to_py(py, &att_resp)?;
        let ext_dict = extension_outputs_to_py(py, &ext_outputs)?;

        Ok(pyo3::types::PyTuple::new(py, [att_dict, ext_dict])?.into())
    }

    /// Perform the full get_assertion operation.
    ///
    /// Takes JSON-serialized options, pre-computed client_data_hash and rp_id.
    /// Returns (assertions_list, extension_outputs_list).
    #[pyo3(signature = (options_json, client_data_hash, rp_id, event=None))]
    fn do_get_assertion(
        &self,
        py: Python<'_>,
        options_json: &str,
        client_data_hash: &[u8],
        rp_id: &str,
        event: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let options: fido2::webauthn::PublicKeyCredentialRequestOptions =
            serde_json::from_str(options_json)
                .map_err(|e| PyValueError::new_err(format!("Invalid options JSON: {}", e)))?;

        let dev = self.make_device(py, event)?;
        let ui = self.make_interaction();
        let backend = self.make_backend(&dev, &ui);

        let (assertions, ext_outputs_list) = backend
            .do_get_assertion(&options, client_data_hash, rp_id)
            .map_err(client_err)?;

        let assertions_py = PyList::empty(py);
        for resp in &assertions {
            assertions_py.append(crate::py_ctap::assertion_response_to_py(py, resp)?)?;
        }

        let ext_list_py = PyList::empty(py);
        for ext_out in &ext_outputs_list {
            ext_list_py.append(extension_outputs_to_py(py, ext_out)?)?;
        }

        Ok(
            pyo3::types::PyTuple::new(py, [assertions_py.into_any(), ext_list_py.into_any()])?
                .into(),
        )
    }
}

/// Convert extension outputs (BTreeMap<String, Value>) to a Python dict.
fn extension_outputs_to_py(
    py: Python<'_>,
    outputs: &fido2::extensions::ExtensionOutputs,
) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (key, value) in outputs {
        dict.set_item(key, crate::py_cbor::value_to_py(py, value)?)?;
    }
    Ok(dict.into())
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "client")?;
    sub.add_class::<ClientDataCollector>()?;
    sub.add_class::<NativeFido2Client>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.client", &sub)?;

    Ok(())
}
