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

use std::collections::BTreeMap;

use fido2::cbor::Value;
use fido2::client::{self, ClientBackend};
use fido2::ctap::capability;
use fido2::ctap2::{self, AssertionResponse, AttestationResponse, Info};
use fido2::extensions::{
    self, AuthenticationExtensionProcessor, Ctap2Extension, ExtensionInputs, ExtensionOutputs,
    RegistrationExtensionProcessor,
};
use fido2::pin::PinProtocol;
use fido2::webauthn::{Aaguid, AuthenticatorData};
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
        client::ClientError::Timeout => PyValueError::new_err("CLIENT_TIMEOUT".to_string()),
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

// ---- Python extension bridge helpers ----

/// Convert a serde_json::Value to a Python object.
fn json_to_py(py: Python<'_>, val: &serde_json::Value) -> PyResult<PyObject> {
    match val {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(n.as_f64().unwrap().into_pyobject(py)?.into_any().unbind())
            }
        }
        serde_json::Value::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        serde_json::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        serde_json::Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

/// Create a Python Ctap2-like proxy with an `info` attribute set from Rust Info.
///
/// Uses `types.SimpleNamespace(info=Info(**info_dict))` so Python extensions
/// can access `ctap.info.extensions`, `ctap.info.options`, etc.
fn create_ctap_proxy(py: Python<'_>, info: &Info) -> PyResult<PyObject> {
    let info_dict = crate::py_ctap::info_to_py(py, info)?;
    let info_mod = py.import("fido2.ctap2")?.getattr("Info")?;
    let info_dict_bound = info_dict.downcast_bound::<PyDict>(py)?;
    let info_obj = info_mod.call((), Some(info_dict_bound))?;

    let types = py.import("types")?;
    let ns_cls = types.getattr("SimpleNamespace")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("info", info_obj)?;
    let proxy = ns_cls.call((), Some(&kwargs))?;
    Ok(proxy.unbind())
}

/// Create a Python options-like proxy with `extensions` and optionally
/// `allow_credentials` attributes.
fn create_options_proxy(
    py: Python<'_>,
    extensions: Option<&serde_json::Value>,
    allow_credentials: Option<&[Value]>,
) -> PyResult<PyObject> {
    let ext_py = match extensions {
        Some(val) => json_to_py(py, val)?,
        None => py.None(),
    };

    let allow_py = match allow_credentials {
        Some(creds) => {
            let list = PyList::empty(py);
            for c in creds {
                list.append(crate::py_cbor::value_to_py(py, c)?)?;
            }
            list.into_any().unbind()
        }
        None => py.None(),
    };

    let types = py.import("types")?;
    let ns_cls = types.getattr("SimpleNamespace")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("extensions", ext_py)?;
    kwargs.set_item("allow_credentials", allow_py)?;
    let proxy = ns_cls.call((), Some(&kwargs))?;
    Ok(proxy.unbind())
}

/// Convert a Python dict (str -> any) to ExtensionInputs (BTreeMap<String, cbor::Value>).
fn py_dict_to_extension_map(py: Python<'_>, obj: &PyObject) -> Option<ExtensionInputs> {
    if obj.is_none(py) {
        return None;
    }
    let bound = obj.bind(py);
    let dict = bound.downcast::<PyDict>().ok()?;
    let mut inputs = ExtensionInputs::new();
    for (key, value) in dict.iter() {
        let k: String = key.extract().ok()?;
        let v = crate::py_cbor::py_to_value(&value).ok()?;
        inputs.insert(k, v);
    }
    Some(inputs)
}

// ---- Python extension bridge (Ctap2Extension) ----

/// Bridges a Python Ctap2Extension to the Rust Ctap2Extension trait.
///
/// Used for pure-Python extensions that don't have a native Rust counterpart.
/// Creates proxy objects for `ctap` and `options` so Python code can access
/// `.info`, `.extensions`, etc.
struct PyExtensionBridge {
    py_obj: PyObject,
}

impl Ctap2Extension for PyExtensionBridge {
    fn is_supported(&self, info: &Info) -> bool {
        Python::with_gil(|py| {
            let proxy = create_ctap_proxy(py, info).ok()?;
            self.py_obj
                .call_method1(py, "is_supported", (proxy,))
                .ok()
                .and_then(|r| r.extract::<bool>(py).ok())
        })
        .unwrap_or(false)
    }

    fn make_credential(
        &self,
        ctap: &ctap2::Ctap2,
        extensions: Option<&serde_json::Value>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn RegistrationExtensionProcessor>> {
        Python::with_gil(|py| {
            let ctap_proxy = create_ctap_proxy(py, ctap.info()).ok()?;
            let options_proxy = create_options_proxy(py, extensions, None).ok()?;
            let pp_py = py.None();

            let result = self
                .py_obj
                .call_method1(py, "make_credential", (ctap_proxy, options_proxy, pp_py))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            Some(Box::new(PyRegistrationProcessorBridge { py_obj: result })
                as Box<dyn RegistrationExtensionProcessor>)
        })
    }

    fn get_assertion(
        &self,
        ctap: &ctap2::Ctap2,
        extensions: Option<&serde_json::Value>,
        allow_credentials: Option<&[Value]>,
        _pin_protocol: Option<PinProtocol>,
    ) -> Option<Box<dyn AuthenticationExtensionProcessor>> {
        Python::with_gil(|py| {
            let ctap_proxy = create_ctap_proxy(py, ctap.info()).ok()?;
            let options_proxy = create_options_proxy(py, extensions, allow_credentials).ok()?;
            let pp_py = py.None();

            let result = self
                .py_obj
                .call_method1(py, "get_assertion", (ctap_proxy, options_proxy, pp_py))
                .ok()?;

            if result.is_none(py) {
                return None;
            }

            Some(Box::new(PyAuthenticationProcessorBridge { py_obj: result })
                as Box<dyn AuthenticationExtensionProcessor>)
        })
    }
}

// ---- Python processor bridges ----

/// Bridges a Python RegistrationExtensionProcessor to the Rust trait.
struct PyRegistrationProcessorBridge {
    py_obj: PyObject,
}

impl RegistrationExtensionProcessor for PyRegistrationProcessorBridge {
    fn permissions(&self) -> u32 {
        Python::with_gil(|py| {
            self.py_obj
                .getattr(py, "permissions")
                .ok()
                .and_then(|p| p.extract::<u32>(py).ok())
        })
        .unwrap_or(0)
    }

    fn prepare_inputs(&self, pin_token: Option<&[u8]>) -> Option<ExtensionInputs> {
        Python::with_gil(|py| {
            let pt_py =
                pin_token.map_or_else(|| py.None(), |t| PyBytes::new(py, t).into_any().unbind());
            let result = self
                .py_obj
                .call_method1(py, "prepare_inputs", (pt_py,))
                .ok()?;
            py_dict_to_extension_map(py, &result)
        })
    }

    fn prepare_outputs(
        &self,
        response: &AttestationResponse,
        pin_token: Option<&[u8]>,
        _ctap: &ctap2::Ctap2,
    ) -> Option<ExtensionOutputs> {
        Python::with_gil(|py| {
            let resp_py = crate::py_ctap::attestation_response_to_py(py, response).ok()?;
            let pt_py =
                pin_token.map_or_else(|| py.None(), |t| PyBytes::new(py, t).into_any().unbind());
            let result = self
                .py_obj
                .call_method1(py, "prepare_outputs", (resp_py, pt_py))
                .ok()?;
            py_dict_to_extension_map(py, &result)
        })
    }
}

/// Bridges a Python AuthenticationExtensionProcessor to the Rust trait.
struct PyAuthenticationProcessorBridge {
    py_obj: PyObject,
}

impl AuthenticationExtensionProcessor for PyAuthenticationProcessorBridge {
    fn permissions(&self) -> u32 {
        Python::with_gil(|py| {
            self.py_obj
                .getattr(py, "permissions")
                .ok()
                .and_then(|p| p.extract::<u32>(py).ok())
        })
        .unwrap_or(0)
    }

    fn prepare_inputs(
        &self,
        selected: Option<&Value>,
        pin_token: Option<&[u8]>,
    ) -> Option<ExtensionInputs> {
        Python::with_gil(|py| {
            let selected_py = selected
                .map_or_else(
                    || Ok(py.None()),
                    |v| crate::py_cbor::value_to_py(py, v).map(|b| b.unbind()),
                )
                .ok()?;
            let pt_py =
                pin_token.map_or_else(|| py.None(), |t| PyBytes::new(py, t).into_any().unbind());
            let result = self
                .py_obj
                .call_method1(py, "prepare_inputs", (selected_py, pt_py))
                .ok()?;
            py_dict_to_extension_map(py, &result)
        })
    }

    fn prepare_outputs(
        &self,
        response: &AssertionResponse,
        pin_token: Option<&[u8]>,
        _ctap: &ctap2::Ctap2,
    ) -> Option<ExtensionOutputs> {
        Python::with_gil(|py| {
            let resp_py = crate::py_ctap::assertion_response_to_py(py, response).ok()?;
            let pt_py =
                pin_token.map_or_else(|| py.None(), |t| PyBytes::new(py, t).into_any().unbind());
            let result = self
                .py_obj
                .call_method1(py, "prepare_outputs", (resp_py, pt_py))
                .ok()?;
            py_dict_to_extension_map(py, &result)
        })
    }
}

// ---- Extension creation from Python objects ----

/// Create Rust extensions from a list of Python extension objects.
///
/// Extensions with a `_native_tag` attribute are recognized as wrappers around
/// Rust implementations and the appropriate native extension is constructed.
/// Extensions without `_native_tag` are wrapped in a `PyExtensionBridge` that
/// calls back into Python.
fn create_extensions_from_py(
    py: Python<'_>,
    py_extensions: &[PyObject],
) -> Vec<Box<dyn Ctap2Extension>> {
    let mut extensions: Vec<Box<dyn Ctap2Extension>> = Vec::new();

    for ext_obj in py_extensions {
        if let Ok(tag) = ext_obj.getattr(py, "_native_tag")
            && let Ok(tag_str) = tag.extract::<String>(py)
        {
            match tag_str.as_str() {
                "hmac_secret" => {
                    let allow = ext_obj
                        .getattr(py, "_allow_hmac_secret")
                        .and_then(|v| v.extract::<bool>(py))
                        .unwrap_or(false);
                    extensions.push(Box::new(extensions::HmacSecretExtension::new(allow)));
                }
                "large_blob" => {
                    extensions.push(Box::new(extensions::LargeBlobExtension));
                }
                "cred_blob" => {
                    extensions.push(Box::new(extensions::CredBlobExtension));
                }
                "cred_protect" => {
                    extensions.push(Box::new(extensions::CredProtectExtension));
                }
                "min_pin_length" => {
                    extensions.push(Box::new(extensions::MinPinLengthExtension));
                }
                "cred_props" => {
                    extensions.push(Box::new(extensions::CredPropsExtension));
                }
                _ => {
                    // Unknown native tag, fall through to Python bridge
                    extensions.push(Box::new(PyExtensionBridge {
                        py_obj: ext_obj.clone_ref(py),
                    }));
                }
            }
            continue;
        }
        // No _native_tag or not a string: wrap as Python extension
        extensions.push(Box::new(PyExtensionBridge {
            py_obj: ext_obj.clone_ref(py),
        }));
    }

    extensions
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
    extensions: Vec<PyObject>,
    enterprise_rpid_list: Option<Vec<String>>,
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
        py: Python<'_>,
        dev: &'a PyCtapDevice,
        ui: &'a PyUserInteraction,
    ) -> Box<dyn ClientBackend + 'a> {
        if self.is_ctap2 {
            let extensions = create_extensions_from_py(py, &self.extensions);
            let mut backend = client::Ctap2Backend::from_parts(
                dev,
                false,
                self.info.max_msg_size,
                ui,
                extensions,
                self.info.clone(),
            );
            backend.set_enterprise_rpid_list(self.enterprise_rpid_list.clone());
            Box::new(backend)
        } else {
            Box::new(client::Ctap1Backend::new(dev, ui))
        }
    }
}

#[pymethods]
impl NativeFido2Client {
    #[new]
    #[pyo3(signature = (device, user_interaction, on_keepalive, extensions=None))]
    fn new(
        py: Python<'_>,
        device: PyObject,
        user_interaction: PyObject,
        on_keepalive: PyObject,
        extensions: Option<PyObject>,
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

        // Extract extension objects from the Python list
        let ext_list: Vec<PyObject> = match extensions {
            Some(ref list_obj) => {
                let bound = list_obj.bind(py);
                let iter = bound.try_iter()?;
                iter.map(|item| item.map(|i| i.unbind()))
                    .collect::<PyResult<Vec<_>>>()?
            }
            None => Vec::new(),
        };

        Ok(Self {
            device,
            user_interaction,
            on_keepalive,
            info,
            is_ctap2,
            extensions: ext_list,
            enterprise_rpid_list: None,
        })
    }

    /// Get cached authenticator info as a Python dict.
    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<PyObject> {
        crate::py_ctap::info_to_py(py, &self.info)
    }

    /// Set the list of RP IDs eligible for platform-managed enterprise attestation.
    #[setter]
    fn set_enterprise_rpid_list(&mut self, py: Python<'_>, value: PyObject) -> PyResult<()> {
        if value.is_none(py) {
            self.enterprise_rpid_list = None;
        } else {
            let bound = value.bind(py);
            let iter = bound.try_iter()?;
            let list: Vec<String> = iter
                .map(|item| item.and_then(|i| i.extract()))
                .collect::<PyResult<_>>()?;
            self.enterprise_rpid_list = Some(list);
        }
        Ok(())
    }

    /// Perform authenticator selection (touch).
    #[pyo3(signature = (event=None))]
    fn selection(&self, py: Python<'_>, event: Option<PyObject>) -> PyResult<()> {
        let dev = self.make_device(py, event)?;
        let ui = self.make_interaction();
        let backend = self.make_backend(py, &dev, &ui);
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
        let backend = self.make_backend(py, &dev, &ui);

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
        let backend = self.make_backend(py, &dev, &ui);

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

// ---- Python → Rust conversion helpers ----

/// Convert a Python Info object to a Rust Info struct.
fn py_to_info(py: Python<'_>, info_obj: &PyObject) -> PyResult<Info> {
    let bound = info_obj.bind(py);

    let versions: Vec<String> = bound
        .getattr("versions")?
        .try_iter()?
        .map(|v| v.and_then(|v| v.extract()))
        .collect::<PyResult<_>>()?;

    let extensions_list: Vec<String> = bound
        .getattr("extensions")?
        .try_iter()?
        .map(|v| v.and_then(|v| v.extract()))
        .collect::<PyResult<_>>()?;

    let aaguid_bytes: Vec<u8> = bound.getattr("aaguid")?.extract()?;
    let aaguid =
        Aaguid::from_slice(&aaguid_bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;

    let options_obj = bound.getattr("options")?;
    let options_dict = options_obj.downcast::<PyDict>()?;
    let mut options = BTreeMap::new();
    for (k, v) in options_dict.iter() {
        options.insert(k.extract::<String>()?, v.extract::<bool>()?);
    }

    let max_msg_size: usize = bound.getattr("max_msg_size")?.extract()?;

    let pin_uv_protocols: Vec<u32> = bound
        .getattr("pin_uv_protocols")?
        .try_iter()?
        .map(|v| v.and_then(|v| v.extract()))
        .collect::<PyResult<_>>()?;

    let max_creds_in_list: usize = bound
        .getattr("max_creds_in_list")?
        .extract::<Option<usize>>()?
        .unwrap_or(0);

    let max_cred_id_length: usize = bound
        .getattr("max_cred_id_length")?
        .extract::<Option<usize>>()?
        .unwrap_or(0);

    let max_cred_blob_length: usize = bound
        .getattr("max_cred_blob_length")?
        .extract::<Option<usize>>()?
        .unwrap_or(0);

    Ok(Info {
        versions,
        extensions: extensions_list,
        aaguid,
        options,
        max_msg_size,
        pin_uv_protocols,
        max_creds_in_list,
        max_cred_id_length,
        max_cred_blob_length,
        ..Info::from_cbor(&[])
    })
}

/// Convert a Python AttestationResponse object to a Rust AttestationResponse.
fn py_to_attestation_response(py: Python<'_>, resp: &PyObject) -> PyResult<AttestationResponse> {
    let bound = resp.bind(py);
    let fmt: String = bound.getattr("fmt")?.extract()?;
    let auth_data_bytes: Vec<u8> = bound.getattr("auth_data")?.extract()?;
    let auth_data = AuthenticatorData::from_bytes(&auth_data_bytes)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let att_stmt_py = bound.getattr("att_stmt")?;
    let att_stmt = crate::py_cbor::py_to_value(&att_stmt_py)?;

    let ep_att: Option<bool> = bound.getattr("ep_att")?.extract()?;
    let large_blob_key: Option<Vec<u8>> = bound.getattr("large_blob_key")?.extract()?;

    Ok(AttestationResponse {
        fmt,
        auth_data,
        att_stmt,
        ep_att,
        large_blob_key,
        unsigned_extension_outputs: BTreeMap::new(),
    })
}

/// Convert a Python AssertionResponse object to a Rust AssertionResponse.
fn py_to_assertion_response(py: Python<'_>, resp: &PyObject) -> PyResult<AssertionResponse> {
    let bound = resp.bind(py);
    let credential_py = bound.getattr("credential")?;
    let credential = crate::py_cbor::py_to_value(&credential_py)?;

    let auth_data_bytes: Vec<u8> = bound.getattr("auth_data")?.extract()?;
    let auth_data = AuthenticatorData::from_bytes(&auth_data_bytes)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let signature: Vec<u8> = bound.getattr("signature")?.extract()?;
    let user_py = bound.getattr("user")?;
    let user = if user_py.is_none() {
        None
    } else {
        Some(crate::py_cbor::py_to_value(&user_py)?)
    };

    let number_of_credentials: Option<u32> = bound.getattr("number_of_credentials")?.extract()?;
    let user_selected: Option<bool> = bound.getattr("user_selected")?.extract()?;
    let large_blob_key: Option<Vec<u8>> = bound.getattr("large_blob_key")?.extract()?;

    Ok(AssertionResponse {
        credential,
        auth_data,
        signature,
        user,
        number_of_credentials,
        user_selected,
        large_blob_key,
    })
}

/// Convert a Python PinProtocol version to a Rust PinProtocol.
fn py_pin_protocol(py: Python<'_>, pp: &PyObject) -> PyResult<Option<PinProtocol>> {
    if pp.is_none(py) {
        return Ok(None);
    }
    let version: u32 = pp.bind(py).getattr("VERSION")?.extract()?;
    match version {
        1 => Ok(Some(PinProtocol::V1)),
        2 => Ok(Some(PinProtocol::V2)),
        _ => Err(PyValueError::new_err("Unsupported protocol version")),
    }
}

/// Convert options.extensions to serde_json::Value.
fn py_options_extensions(
    py: Python<'_>,
    options: &PyObject,
) -> PyResult<Option<serde_json::Value>> {
    let ext = options.bind(py).getattr("extensions")?;
    if ext.is_none() {
        return Ok(None);
    }
    let json_str = py
        .import("json")?
        .call_method1("dumps", (&ext,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str)
        .map(Some)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Convert options.allow_credentials to Vec<Value> (CBOR).
fn py_allow_credentials(py: Python<'_>, options: &PyObject) -> PyResult<Option<Vec<Value>>> {
    let ac = options.bind(py).getattr("allow_credentials")?;
    if ac.is_none() {
        return Ok(None);
    }
    let iter = ac.try_iter()?;
    let mut creds = Vec::new();
    for item in iter {
        creds.push(crate::py_cbor::py_to_value(&item?)?);
    }
    Ok(Some(creds))
}

// ---- NativeExtension ----

/// A native CTAP2 extension exposed to Python.
///
/// Wraps a Rust Ctap2Extension trait object and exposes its methods to Python.
/// The Python extension classes delegate to this for their logic.
#[pyclass]
struct NativeExtension {
    inner: std::sync::Mutex<Box<dyn Ctap2Extension + Send>>,
}

#[pymethods]
impl NativeExtension {
    #[staticmethod]
    fn hmac_secret(allow_hmac_secret: bool) -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::new(extensions::HmacSecretExtension::new(
                allow_hmac_secret,
            ))),
        }
    }

    #[staticmethod]
    fn large_blob() -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::new(extensions::LargeBlobExtension)),
        }
    }

    #[staticmethod]
    fn cred_blob() -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::new(extensions::CredBlobExtension)),
        }
    }

    #[staticmethod]
    fn cred_protect() -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::new(extensions::CredProtectExtension)),
        }
    }

    #[staticmethod]
    fn min_pin_length() -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::new(extensions::MinPinLengthExtension)),
        }
    }

    #[staticmethod]
    fn cred_props() -> Self {
        Self {
            inner: std::sync::Mutex::new(Box::new(extensions::CredPropsExtension)),
        }
    }

    /// Check if the extension is supported by the authenticator.
    fn is_supported(&self, py: Python<'_>, ctap: PyObject) -> PyResult<bool> {
        let info_obj = ctap.bind(py).getattr("info")?.unbind();
        let info = py_to_info(py, &info_obj)?;
        let inner = self.inner.lock().unwrap();
        Ok(inner.is_supported(&info))
    }

    /// Create a registration processor.
    fn make_credential(
        &self,
        py: Python<'_>,
        ctap: PyObject,
        options: PyObject,
        pin_protocol: PyObject,
    ) -> PyResult<Option<NativeRegistrationProcessor>> {
        let native = ctap.bind(py).getattr("_native")?;
        let device: PyObject = native.getattr("device")?.unbind();
        let strict_cbor: bool = native.getattr("strict_cbor")?.extract()?;
        let max_msg_size: usize = native.getattr("max_msg_size")?.extract()?;

        let dev = PyCtapDevice::new(py, device.clone_ref(py))?;
        let info_obj = ctap.bind(py).getattr("info")?.unbind();
        let info = py_to_info(py, &info_obj)?;
        let mut ctap2 = ctap2::Ctap2::from_parts(&dev, strict_cbor, max_msg_size);
        ctap2.set_info(info);

        let ext_json = py_options_extensions(py, &options)?;
        let pp = py_pin_protocol(py, &pin_protocol)?;

        let inner = self.inner.lock().unwrap();
        let processor = inner.make_credential(&ctap2, ext_json.as_ref(), pp);
        Ok(processor.map(|p| NativeRegistrationProcessor {
            inner: p,
            device,
            strict_cbor,
            max_msg_size,
        }))
    }

    /// Create an authentication processor.
    fn get_assertion(
        &self,
        py: Python<'_>,
        ctap: PyObject,
        options: PyObject,
        pin_protocol: PyObject,
    ) -> PyResult<Option<NativeAuthenticationProcessor>> {
        let native = ctap.bind(py).getattr("_native")?;
        let device: PyObject = native.getattr("device")?.unbind();
        let strict_cbor: bool = native.getattr("strict_cbor")?.extract()?;
        let max_msg_size: usize = native.getattr("max_msg_size")?.extract()?;

        let dev = PyCtapDevice::new(py, device.clone_ref(py))?;
        let info_obj = ctap.bind(py).getattr("info")?.unbind();
        let info = py_to_info(py, &info_obj)?;
        let mut ctap2 = ctap2::Ctap2::from_parts(&dev, strict_cbor, max_msg_size);
        ctap2.set_info(info);

        let ext_json = py_options_extensions(py, &options)?;
        let allow_creds = py_allow_credentials(py, &options)?;
        let pp = py_pin_protocol(py, &pin_protocol)?;

        let inner = self.inner.lock().unwrap();
        let processor = inner.get_assertion(&ctap2, ext_json.as_ref(), allow_creds.as_deref(), pp);
        Ok(processor.map(|p| NativeAuthenticationProcessor {
            inner: p,
            device,
            strict_cbor,
            max_msg_size,
        }))
    }
}

// ---- NativeRegistrationProcessor ----

/// Wraps a Rust RegistrationExtensionProcessor for use from Python.
#[pyclass(unsendable)]
struct NativeRegistrationProcessor {
    inner: Box<dyn RegistrationExtensionProcessor>,
    device: PyObject,
    strict_cbor: bool,
    max_msg_size: usize,
}

#[pymethods]
impl NativeRegistrationProcessor {
    #[getter]
    fn permissions(&self) -> u32 {
        self.inner.permissions()
    }

    fn prepare_inputs(
        &self,
        py: Python<'_>,
        pin_token: Option<&[u8]>,
    ) -> PyResult<Option<PyObject>> {
        match self.inner.prepare_inputs(pin_token) {
            Some(inputs) => Ok(Some(extension_outputs_to_py(py, &inputs)?)),
            None => Ok(None),
        }
    }

    fn prepare_outputs(
        &self,
        py: Python<'_>,
        response: PyObject,
        pin_token: Option<&[u8]>,
    ) -> PyResult<Option<PyObject>> {
        let att_resp = py_to_attestation_response(py, &response)?;
        let dev = PyCtapDevice::new(py, self.device.clone_ref(py))?;
        let ctap = ctap2::Ctap2::from_parts(&dev, self.strict_cbor, self.max_msg_size);

        match self.inner.prepare_outputs(&att_resp, pin_token, &ctap) {
            Some(outputs) => Ok(Some(extension_outputs_to_py(py, &outputs)?)),
            None => Ok(None),
        }
    }
}

// ---- NativeAuthenticationProcessor ----

/// Wraps a Rust AuthenticationExtensionProcessor for use from Python.
#[pyclass(unsendable)]
struct NativeAuthenticationProcessor {
    inner: Box<dyn AuthenticationExtensionProcessor>,
    device: PyObject,
    strict_cbor: bool,
    max_msg_size: usize,
}

#[pymethods]
impl NativeAuthenticationProcessor {
    #[getter]
    fn permissions(&self) -> u32 {
        self.inner.permissions()
    }

    fn prepare_inputs(
        &self,
        py: Python<'_>,
        selected: PyObject,
        pin_token: Option<&[u8]>,
    ) -> PyResult<Option<PyObject>> {
        let sel = if selected.is_none(py) {
            None
        } else {
            Some(crate::py_cbor::py_to_value(selected.bind(py))?)
        };

        match self.inner.prepare_inputs(sel.as_ref(), pin_token) {
            Some(inputs) => Ok(Some(extension_outputs_to_py(py, &inputs)?)),
            None => Ok(None),
        }
    }

    fn prepare_outputs(
        &self,
        py: Python<'_>,
        response: PyObject,
        pin_token: Option<&[u8]>,
    ) -> PyResult<Option<PyObject>> {
        let ass_resp = py_to_assertion_response(py, &response)?;
        let dev = PyCtapDevice::new(py, self.device.clone_ref(py))?;
        let ctap = ctap2::Ctap2::from_parts(&dev, self.strict_cbor, self.max_msg_size);

        match self.inner.prepare_outputs(&ass_resp, pin_token, &ctap) {
            Some(outputs) => Ok(Some(extension_outputs_to_py(py, &outputs)?)),
            None => Ok(None),
        }
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "client")?;
    sub.add_class::<ClientDataCollector>()?;
    sub.add_class::<NativeFido2Client>()?;
    sub.add_class::<NativeExtension>()?;
    sub.add_class::<NativeRegistrationProcessor>()?;
    sub.add_class::<NativeAuthenticationProcessor>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.client", &sub)?;

    Ok(())
}
