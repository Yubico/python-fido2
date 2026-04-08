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

//! PyO3 wrappers for CTAP1 and CTAP2 protocols.

use crate::py_cbor;
use fido2_client::bio::FPBioEnrollment;
use fido2_client::blob::LargeBlobs;
use fido2_client::config::Config;
use fido2_client::credman::CredentialManagement;
use fido2_client::ctap::{ApduError, CtapDevice, CtapError};
use fido2_client::ctap1;
use fido2_client::ctap2::{self, AssertionResponse, AttestationResponse, Info};
use fido2_client::pin::{ClientPin, PinProtocol};
use fido2_server::cbor::Value;
use pyo3::exceptions::{PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

// ---- Bridge: Python CtapDevice -> Rust CtapDevice trait ----

// Thread-local storage for Python event/on_keepalive objects.
// Set before calling into Rust Ctap2 methods and consumed by PyCtapDevice::call().
thread_local! {
    static CALL_EVENT: std::cell::RefCell<Option<PyObject>> = const { std::cell::RefCell::new(None) };
    static CALL_ON_KEEPALIVE: std::cell::RefCell<Option<PyObject>> = const { std::cell::RefCell::new(None) };
}

/// Set the Python event/on_keepalive for the current call, execute `f`, then clear them.
pub(crate) fn with_event_args<R>(
    event: Option<PyObject>,
    on_keepalive: Option<PyObject>,
    f: impl FnOnce() -> R,
) -> R {
    CALL_EVENT.with(|e| *e.borrow_mut() = event);
    CALL_ON_KEEPALIVE.with(|k| *k.borrow_mut() = on_keepalive);
    let result = f();
    CALL_EVENT.with(|e| *e.borrow_mut() = None);
    CALL_ON_KEEPALIVE.with(|k| *k.borrow_mut() = None);
    result
}

/// Wraps a Python CtapDevice object to implement the Rust CtapDevice trait.
///
/// If event/on_keepalive are set in thread-local storage (via `with_event_args`),
/// they are passed to the Python `device.call()`. Otherwise only cmd and data are passed.
pub struct PyCtapDevice {
    py_device: PyObject,
    capabilities: u8,
}

impl PyCtapDevice {
    pub fn new(py: Python<'_>, py_device: PyObject) -> PyResult<Self> {
        let capabilities: u8 = py_device.getattr(py, "capabilities")?.extract(py)?;
        Ok(Self {
            py_device,
            capabilities,
        })
    }
}

impl CtapDevice for PyCtapDevice {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        _on_keepalive: &mut dyn FnMut(u8),
        _cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, CtapError> {
        Python::with_gil(|py| {
            let event = CALL_EVENT.with(|e| e.borrow().as_ref().map(|v| v.clone_ref(py)));
            let on_keepalive =
                CALL_ON_KEEPALIVE.with(|k| k.borrow().as_ref().map(|v| v.clone_ref(py)));

            let result = if event.is_some() || on_keepalive.is_some() {
                self.py_device.call_method1(
                    py,
                    "call",
                    (
                        cmd,
                        PyBytes::new(py, data),
                        event.unwrap_or_else(|| py.None()),
                        on_keepalive.unwrap_or_else(|| py.None()),
                    ),
                )
            } else {
                self.py_device
                    .call_method1(py, "call", (cmd, PyBytes::new(py, data)))
            }
            .map_err(|e| CtapError::TransportError(e.to_string()))?;

            result
                .extract(py)
                .map_err(|e| CtapError::TransportError(e.to_string()))
        })
    }

    fn capabilities(&self) -> u8 {
        self.capabilities
    }
}

// ---- Error conversion helpers ----

pub fn ctap_err(e: CtapError) -> PyErr {
    match e {
        CtapError::StatusError(status) => Python::with_gil(|py| match py.import("fido2.ctap") {
            Ok(m) => match m.getattr("CtapError") {
                Ok(cls) => match cls.call1((status.as_byte(),)) {
                    Ok(inst) => PyErr::from_value(inst.into_any()),
                    Err(e) => e,
                },
                Err(e) => e,
            },
            Err(e) => e,
        }),
        CtapError::InvalidResponse(ref msg) if msg.starts_with("Invalid PIN:") => {
            PyValueError::new_err(msg.clone())
        }
        _ => PyOSError::new_err(e.to_string()),
    }
}

fn apdu_err(e: ApduError) -> PyErr {
    let data_hex: String = e.data.iter().map(|b| format!("{:02x}", b)).collect();
    PyValueError::new_err(format!("APDU_ERR:{}:{}", e.code, data_hex))
}

// ---- Conversion helpers ----

pub fn py_to_val(py: Python<'_>, obj: PyObject) -> PyResult<fido2_server::cbor::Value> {
    py_cbor::py_to_value(obj.bind(py))
}

fn py_opt_to_val(
    py: Python<'_>,
    obj: Option<PyObject>,
) -> PyResult<Option<fido2_server::cbor::Value>> {
    obj.map(|o| py_to_val(py, o)).transpose()
}

pub fn val_to_pyobj(py: Python<'_>, val: &fido2_server::cbor::Value) -> PyResult<PyObject> {
    Ok(py_cbor::value_to_py(py, val)?.unbind())
}

pub fn info_to_py(py: Python<'_>, info: &Info) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item(
        "versions",
        PyList::new(py, info.versions.iter().map(|s| s.as_str()))?,
    )?;
    dict.set_item(
        "extensions",
        PyList::new(py, info.extensions.iter().map(|s| s.as_str()))?,
    )?;
    dict.set_item("aaguid", PyBytes::new(py, info.aaguid.as_bytes()))?;
    let opts = PyDict::new(py);
    for (k, v) in &info.options {
        opts.set_item(k, *v)?;
    }
    dict.set_item("options", opts)?;
    dict.set_item("max_msg_size", info.max_msg_size)?;
    dict.set_item(
        "pin_uv_protocols",
        PyList::new(py, info.pin_uv_protocols.iter())?,
    )?;
    dict.set_item("max_creds_in_list", info.max_creds_in_list)?;
    dict.set_item("max_cred_id_length", info.max_cred_id_length)?;
    dict.set_item(
        "transports",
        PyList::new(py, info.transports.iter().map(|s| s.as_str()))?,
    )?;
    let alg_list = PyList::empty(py);
    for alg in &info.algorithms {
        let d = PyDict::new(py);
        for (k, v) in alg {
            d.set_item(k, py_cbor::value_to_py(py, v)?)?;
        }
        alg_list.append(d)?;
    }
    dict.set_item("algorithms", alg_list)?;
    dict.set_item("max_large_blob", info.max_large_blob)?;
    dict.set_item("force_pin_change", info.force_pin_change)?;
    dict.set_item("min_pin_length", info.min_pin_length)?;
    dict.set_item("firmware_version", info.firmware_version)?;
    dict.set_item("max_cred_blob_length", info.max_cred_blob_length)?;
    dict.set_item("max_rpids_for_min_pin", info.max_rpids_for_min_pin)?;
    dict.set_item(
        "preferred_platform_uv_attempts",
        info.preferred_platform_uv_attempts,
    )?;
    dict.set_item("uv_modality", info.uv_modality)?;
    dict.set_item(
        "remaining_disc_creds",
        info.remaining_disc_creds.map(|n| n as i64),
    )?;
    dict.set_item(
        "attestation_formats",
        PyList::new(py, info.attestation_formats.iter().map(|s| s.as_str()))?,
    )?;
    Ok(dict.into())
}

pub fn attestation_response_to_py(
    py: Python<'_>,
    resp: &AttestationResponse,
) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("fmt", &resp.fmt)?;
    dict.set_item("auth_data", PyBytes::new(py, resp.auth_data.as_bytes()))?;
    dict.set_item("att_stmt", py_cbor::value_to_py(py, &resp.att_stmt)?)?;
    dict.set_item("ep_att", resp.ep_att)?;
    dict.set_item(
        "large_blob_key",
        resp.large_blob_key.as_ref().map(|b| PyBytes::new(py, b)),
    )?;
    let ext = PyDict::new(py);
    for (k, v) in &resp.unsigned_extension_outputs {
        ext.set_item(k, py_cbor::value_to_py(py, v)?)?;
    }
    dict.set_item("unsigned_extension_outputs", ext)?;
    Ok(dict.into())
}

pub fn assertion_response_to_py(py: Python<'_>, resp: &AssertionResponse) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("credential", py_cbor::value_to_py(py, &resp.credential)?)?;
    dict.set_item("auth_data", PyBytes::new(py, resp.auth_data.as_bytes()))?;
    dict.set_item("signature", PyBytes::new(py, &resp.signature))?;
    dict.set_item(
        "user",
        resp.user
            .as_ref()
            .map(|u| py_cbor::value_to_py(py, u))
            .transpose()?,
    )?;
    dict.set_item(
        "number_of_credentials",
        resp.number_of_credentials.map(|n| n as i64),
    )?;
    dict.set_item("user_selected", resp.user_selected)?;
    dict.set_item(
        "large_blob_key",
        resp.large_blob_key.as_ref().map(|b| PyBytes::new(py, b)),
    )?;
    Ok(dict.into())
}

// ---- NativeCtap1 ----

#[pyclass]
struct NativeCtap1 {
    inner: ctap1::Ctap1<PyCtapDevice>,
}

#[pymethods]
impl NativeCtap1 {
    #[new]
    fn new(py: Python<'_>, device: PyObject) -> PyResult<Self> {
        let dev = PyCtapDevice::new(py, device)?;
        Ok(Self {
            inner: ctap1::Ctap1::new(dev),
        })
    }

    fn send_apdu<'py>(
        &mut self,
        py: Python<'py>,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let resp = self
            .inner
            .send_apdu(cla, ins, p1, p2, data)
            .map_err(apdu_err)?;
        Ok(PyBytes::new(py, &resp))
    }

    fn get_version(&mut self) -> PyResult<String> {
        self.inner.get_version().map_err(apdu_err)
    }

    fn register<'py>(
        &mut self,
        py: Python<'py>,
        client_param: &[u8],
        app_param: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(client_param);
        data.extend_from_slice(app_param);
        let response = self
            .inner
            .send_apdu(0, ctap1::ins::REGISTER, 0, 0, &data)
            .map_err(apdu_err)?;
        Ok(PyBytes::new(py, &response))
    }

    #[pyo3(signature = (client_param, app_param, key_handle, check_only=false))]
    fn authenticate<'py>(
        &mut self,
        py: Python<'py>,
        client_param: &[u8],
        app_param: &[u8],
        key_handle: &[u8],
        check_only: bool,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut data = Vec::with_capacity(65 + key_handle.len());
        data.extend_from_slice(client_param);
        data.extend_from_slice(app_param);
        data.push(key_handle.len() as u8);
        data.extend_from_slice(key_handle);
        let p1 = if check_only { 0x07 } else { 0x03 };
        let response = self
            .inner
            .send_apdu(0, ctap1::ins::AUTHENTICATE, p1, 0, &data)
            .map_err(apdu_err)?;
        Ok(PyBytes::new(py, &response))
    }
}

// ---- NativeCtap2 ----

#[pyclass]
pub(crate) struct NativeCtap2 {
    device: PyObject,
    strict_cbor: bool,
    max_msg_size: usize,
    inner: ctap2::Ctap2<PyCtapDevice>,
}

#[pymethods]
impl NativeCtap2 {
    #[new]
    #[pyo3(signature = (device, strict_cbor=true, max_msg_size=1024))]
    fn new(
        py: Python<'_>,
        device: PyObject,
        strict_cbor: bool,
        max_msg_size: usize,
    ) -> PyResult<Self> {
        let dev = PyCtapDevice::new(py, device.clone_ref(py))?;
        Ok(Self {
            device,
            strict_cbor,
            max_msg_size,
            inner: ctap2::Ctap2::from_parts(dev, strict_cbor, max_msg_size),
        })
    }

    #[getter]
    fn device(&self, py: Python<'_>) -> PyObject {
        self.device.clone_ref(py)
    }

    #[getter]
    fn info(&self, py: Python<'_>) -> PyResult<PyObject> {
        info_to_py(py, self.inner.info())
    }

    #[pyo3(signature = (cmd, data=None, event=None, on_keepalive=None))]
    fn send_cbor(
        &mut self,
        py: Python<'_>,
        cmd: u8,
        data: Option<PyObject>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let cbor_data = py_opt_to_val(py, data)?;
        let result = with_event_args(event, on_keepalive, || {
            self.inner
                .send_cbor(cmd, cbor_data.as_ref(), &mut |_| {}, None)
        })
        .map_err(ctap_err)?;

        // Update info when GET_INFO is called
        if cmd == ctap2::ctap2_cmd::GET_INFO
            && let Value::Map(ref entries) = result
        {
            let info = Info::from_cbor(entries);
            self.max_msg_size = info.max_msg_size;
            self.inner.set_info(info);
        }

        val_to_pyobj(py, &result)
    }

    fn refresh_info(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let info = self.inner.get_info().map_err(ctap_err)?;
        let result = info_to_py(py, &info)?;
        self.max_msg_size = info.max_msg_size;
        self.inner.set_info(info);
        Ok(result)
    }

    #[pyo3(signature = (
        client_data_hash, rp, user, key_params,
        exclude_list=None, extensions=None, options=None,
        pin_uv_param=None, pin_uv_protocol=None,
        enterprise_attestation=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn make_credential(
        &mut self,
        py: Python<'_>,
        client_data_hash: &[u8],
        rp: PyObject,
        user: PyObject,
        key_params: PyObject,
        exclude_list: Option<PyObject>,
        extensions: Option<PyObject>,
        options: Option<PyObject>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        enterprise_attestation: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let rp_val = py_to_val(py, rp)?;
        let user_val = py_to_val(py, user)?;
        let key_params_val = py_to_val(py, key_params)?;
        let exclude_val = py_opt_to_val(py, exclude_list)?;
        let ext_val = py_opt_to_val(py, extensions)?;
        let opts_val = py_opt_to_val(py, options)?;

        let resp = with_event_args(event, on_keepalive, || {
            self.inner.make_credential(
                client_data_hash,
                rp_val,
                user_val,
                key_params_val,
                exclude_val,
                ext_val,
                opts_val,
                pin_uv_param,
                pin_uv_protocol,
                enterprise_attestation,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;

        attestation_response_to_py(py, &resp)
    }

    #[pyo3(signature = (
        rp_id, client_data_hash,
        allow_list=None, extensions=None, options=None,
        pin_uv_param=None, pin_uv_protocol=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn get_assertion(
        &mut self,
        py: Python<'_>,
        rp_id: &str,
        client_data_hash: &[u8],
        allow_list: Option<PyObject>,
        extensions: Option<PyObject>,
        options: Option<PyObject>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let allow_val = py_opt_to_val(py, allow_list)?;
        let ext_val = py_opt_to_val(py, extensions)?;
        let opts_val = py_opt_to_val(py, options)?;

        let resp = with_event_args(event, on_keepalive, || {
            self.inner.get_assertion(
                rp_id,
                client_data_hash,
                allow_val,
                ext_val,
                opts_val,
                pin_uv_param,
                pin_uv_protocol,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;

        assertion_response_to_py(py, &resp)
    }

    fn get_next_assertion(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let resp = self.inner.get_next_assertion().map_err(ctap_err)?;
        assertion_response_to_py(py, &resp)
    }

    #[pyo3(signature = (
        rp_id, client_data_hash,
        allow_list=None, extensions=None, options=None,
        pin_uv_param=None, pin_uv_protocol=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn get_assertions(
        &mut self,
        py: Python<'_>,
        rp_id: &str,
        client_data_hash: &[u8],
        allow_list: Option<PyObject>,
        extensions: Option<PyObject>,
        options: Option<PyObject>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let allow_val = py_opt_to_val(py, allow_list)?;
        let ext_val = py_opt_to_val(py, extensions)?;
        let opts_val = py_opt_to_val(py, options)?;

        let results = with_event_args(event, on_keepalive, || {
            self.inner.get_assertions(
                rp_id,
                client_data_hash,
                allow_val,
                ext_val,
                opts_val,
                pin_uv_param,
                pin_uv_protocol,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;

        let list = PyList::empty(py);
        for resp in &results {
            list.append(assertion_response_to_py(py, resp)?)?;
        }
        Ok(list.into())
    }

    #[pyo3(signature = (
        pin_uv_protocol, sub_cmd,
        key_agreement=None, pin_uv_param=None,
        new_pin_enc=None, pin_hash_enc=None,
        permissions=None, permissions_rpid=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn client_pin(
        &mut self,
        py: Python<'_>,
        pin_uv_protocol: u32,
        sub_cmd: u32,
        key_agreement: Option<PyObject>,
        pin_uv_param: Option<&[u8]>,
        new_pin_enc: Option<&[u8]>,
        pin_hash_enc: Option<&[u8]>,
        permissions: Option<u32>,
        permissions_rpid: Option<&str>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let ka_val = py_opt_to_val(py, key_agreement)?;

        let result = with_event_args(event, on_keepalive, || {
            self.inner.client_pin(
                pin_uv_protocol,
                sub_cmd,
                ka_val,
                pin_uv_param,
                new_pin_enc,
                pin_hash_enc,
                permissions,
                permissions_rpid,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;

        val_to_pyobj(py, &result)
    }

    #[pyo3(signature = (event=None, on_keepalive=None))]
    fn selection(
        &mut self,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<()> {
        with_event_args(event, on_keepalive, || {
            self.inner.selection(&mut |_| {}, None)
        })
        .map_err(ctap_err)
    }

    #[pyo3(signature = (event=None, on_keepalive=None))]
    fn reset(&mut self, event: Option<PyObject>, on_keepalive: Option<PyObject>) -> PyResult<()> {
        with_event_args(event, on_keepalive, || self.inner.reset(&mut |_| {}, None))
            .map_err(ctap_err)
    }

    #[pyo3(signature = (
        sub_cmd,
        sub_cmd_params=None, pin_uv_protocol=None, pin_uv_param=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn credential_mgmt(
        &mut self,
        py: Python<'_>,
        sub_cmd: PyObject,
        sub_cmd_params: Option<PyObject>,
        pin_uv_protocol: Option<PyObject>,
        pin_uv_param: Option<PyObject>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let sub_cmd_val = py_to_val(py, sub_cmd)?;
        let params_val = py_opt_to_val(py, sub_cmd_params)?;
        let proto_val = py_opt_to_val(py, pin_uv_protocol)?;
        let param_val = py_opt_to_val(py, pin_uv_param)?;

        let result = with_event_args(event, on_keepalive, || {
            self.inner.credential_mgmt(
                sub_cmd_val,
                params_val,
                proto_val,
                param_val,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    #[pyo3(signature = (
        modality=None, sub_cmd=None, sub_cmd_params=None,
        pin_uv_protocol=None, pin_uv_param=None, get_modality=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn bio_enrollment(
        &mut self,
        py: Python<'_>,
        modality: Option<PyObject>,
        sub_cmd: Option<PyObject>,
        sub_cmd_params: Option<PyObject>,
        pin_uv_protocol: Option<PyObject>,
        pin_uv_param: Option<PyObject>,
        get_modality: Option<PyObject>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let mod_val = py_opt_to_val(py, modality)?;
        let cmd_val = py_opt_to_val(py, sub_cmd)?;
        let params_val = py_opt_to_val(py, sub_cmd_params)?;
        let proto_val = py_opt_to_val(py, pin_uv_protocol)?;
        let param_val = py_opt_to_val(py, pin_uv_param)?;
        let gm_val = py_opt_to_val(py, get_modality)?;

        let result = with_event_args(event, on_keepalive, || {
            self.inner.bio_enrollment(
                mod_val,
                cmd_val,
                params_val,
                proto_val,
                param_val,
                gm_val,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    #[pyo3(signature = (
        offset, get=None, set=None, length=None,
        pin_uv_param=None, pin_uv_protocol=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn large_blobs(
        &mut self,
        py: Python<'_>,
        offset: u64,
        get: Option<u64>,
        set: Option<&[u8]>,
        length: Option<u64>,
        pin_uv_param: Option<&[u8]>,
        pin_uv_protocol: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let result = with_event_args(event, on_keepalive, || {
            self.inner.large_blobs(
                offset,
                get,
                set,
                length,
                pin_uv_param,
                pin_uv_protocol,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    #[pyo3(signature = (
        sub_cmd, sub_cmd_params=None,
        pin_uv_protocol=None, pin_uv_param=None,
        event=None, on_keepalive=None
    ))]
    #[allow(clippy::too_many_arguments)]
    fn config(
        &mut self,
        py: Python<'_>,
        sub_cmd: PyObject,
        sub_cmd_params: Option<PyObject>,
        pin_uv_protocol: Option<PyObject>,
        pin_uv_param: Option<PyObject>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let cmd_val = py_to_val(py, sub_cmd)?;
        let params_val = py_opt_to_val(py, sub_cmd_params)?;
        let proto_val = py_opt_to_val(py, pin_uv_protocol)?;
        let param_val = py_opt_to_val(py, pin_uv_param)?;

        let result = with_event_args(event, on_keepalive, || {
            self.inner
                .config(cmd_val, params_val, proto_val, param_val, &mut |_| {}, None)
        })
        .map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }
}

impl NativeCtap2 {
    /// Create a new Ctap2<PyCtapDevice> for session types that need their own.
    pub(crate) fn make_ctap(&self, py: Python<'_>) -> PyResult<ctap2::Ctap2<PyCtapDevice>> {
        let dev = PyCtapDevice::new(py, self.device.clone_ref(py))?;
        let mut ctap = ctap2::Ctap2::from_parts(dev, self.strict_cbor, self.max_msg_size);
        ctap.set_info(self.inner.info().clone());
        Ok(ctap)
    }
}

// ---- Helper: make PinProtocol from version ----

fn make_protocol(version: u32) -> PyResult<PinProtocol> {
    match version {
        1 => Ok(PinProtocol::V1),
        2 => Ok(PinProtocol::V2),
        _ => Err(PyValueError::new_err("Unsupported protocol version")),
    }
}

// ---- NativeClientPin ----

#[pyclass]
struct NativeClientPin {
    inner: ClientPin<PyCtapDevice>,
}

#[pymethods]
impl NativeClientPin {
    #[new]
    fn new(ctap: &NativeCtap2, py: Python<'_>, protocol_version: u32) -> PyResult<Self> {
        let ctap2 = ctap.make_ctap(py)?;
        let protocol = make_protocol(protocol_version)?;
        let inner = ClientPin::new(ctap2, Some(protocol)).map_err(ctap_err)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn is_supported(info: PyObject, py: Python<'_>) -> PyResult<bool> {
        let options: PyObject = info.getattr(py, "options")?;
        let contains: bool = options
            .call_method1(py, "__contains__", ("clientPin",))?
            .extract(py)?;
        Ok(contains)
    }

    #[staticmethod]
    fn is_token_supported(info: PyObject, py: Python<'_>) -> PyResult<bool> {
        let options: &Bound<'_, PyAny> = &info.getattr(py, "options")?.into_bound(py);
        let val = options.call_method1("get", ("pinUvAuthToken",))?;
        Ok(val.is_truthy()? && val.extract::<bool>().unwrap_or(false))
    }

    #[pyo3(signature = (pin, permissions=None, permissions_rpid=None))]
    fn get_pin_token<'py>(
        &mut self,
        py: Python<'py>,
        pin: &str,
        permissions: Option<u32>,
        permissions_rpid: Option<&str>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let token = self
            .inner
            .get_pin_token(pin, permissions, permissions_rpid)
            .map_err(ctap_err)?;
        Ok(PyBytes::new(py, &token))
    }

    #[pyo3(signature = (permissions=None, permissions_rpid=None, event=None, on_keepalive=None))]
    fn get_uv_token<'py>(
        &mut self,
        py: Python<'py>,
        permissions: Option<u32>,
        permissions_rpid: Option<&str>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let token = with_event_args(event, on_keepalive, || {
            self.inner.get_uv_token(
                permissions.unwrap_or(0),
                permissions_rpid,
                &mut |_| {},
                None,
            )
        })
        .map_err(ctap_err)?;
        Ok(PyBytes::new(py, &token))
    }

    fn get_pin_retries(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let (retries, power_cycle) = self.inner.get_pin_retries().map_err(ctap_err)?;
        Ok(PyTuple::new(
            py,
            [
                retries.into_pyobject(py)?.into_any(),
                power_cycle
                    .map(|v| v.into_pyobject(py).map(|o| o.into_any()))
                    .transpose()?
                    .unwrap_or_else(|| py.None().into_bound(py)),
            ],
        )?
        .into())
    }

    fn get_uv_retries(&mut self) -> PyResult<u32> {
        self.inner.get_uv_retries().map_err(ctap_err)
    }

    fn set_pin(&mut self, pin: &str) -> PyResult<()> {
        self.inner.set_pin(pin).map_err(ctap_err)
    }

    fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> PyResult<()> {
        self.inner.change_pin(old_pin, new_pin).map_err(ctap_err)
    }

    fn get_shared_secret(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let (ka, shared) = self.inner._get_shared_secret().map_err(ctap_err)?;

        let ka_dict = PyDict::new(py);
        ka_dict.set_item(1i32, 2i32)?;
        ka_dict.set_item(3i32, -25i32)?;
        ka_dict.set_item(-1i32, 1i32)?;
        ka_dict.set_item(-2i32, PyBytes::new(py, &ka.x))?;
        ka_dict.set_item(-3i32, PyBytes::new(py, &ka.y))?;

        let shared_bytes = PyBytes::new(py, &shared);
        Ok(PyTuple::new(py, [ka_dict.into_any(), shared_bytes.into_any()])?.into())
    }
}

// ---- NativeCredentialManagement ----

#[pyclass]
struct NativeCredentialManagement {
    inner: CredentialManagement<PyCtapDevice>,
}

#[pymethods]
impl NativeCredentialManagement {
    #[new]
    fn new(
        ctap: &NativeCtap2,
        py: Python<'_>,
        protocol_version: u32,
        pin_uv_token: Vec<u8>,
    ) -> PyResult<Self> {
        let ctap2 = ctap.make_ctap(py)?;
        let protocol = make_protocol(protocol_version)?;
        let inner = CredentialManagement::new(ctap2, protocol, pin_uv_token);
        Ok(Self { inner })
    }

    fn get_metadata(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let result = self.inner.get_metadata().map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    fn enumerate_rps_begin(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let result = self.inner.enumerate_rps_begin().map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    fn enumerate_rps_next(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let result = self.inner.enumerate_rps_next().map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    fn enumerate_rps(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let results = self.inner.enumerate_rps().map_err(ctap_err)?;
        let list = PyList::empty(py);
        for v in &results {
            list.append(py_cbor::value_to_py(py, v)?)?;
        }
        Ok(list.into())
    }

    fn enumerate_creds_begin(&mut self, py: Python<'_>, rp_id_hash: &[u8]) -> PyResult<PyObject> {
        let result = self
            .inner
            .enumerate_creds_begin(rp_id_hash)
            .map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    fn enumerate_creds_next(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let result = self.inner.enumerate_creds_next().map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    fn enumerate_creds(&mut self, py: Python<'_>, rp_id_hash: &[u8]) -> PyResult<PyObject> {
        let results = self.inner.enumerate_creds(rp_id_hash).map_err(ctap_err)?;
        let list = PyList::empty(py);
        for v in &results {
            list.append(py_cbor::value_to_py(py, v)?)?;
        }
        Ok(list.into())
    }

    fn delete_cred(&mut self, py: Python<'_>, cred_id: PyObject) -> PyResult<()> {
        let cred_val = py_to_val(py, cred_id)?;
        self.inner.delete_cred(cred_val).map_err(ctap_err)
    }

    fn update_user_info(
        &mut self,
        py: Python<'_>,
        cred_id: PyObject,
        user: PyObject,
    ) -> PyResult<()> {
        let cred_val = py_to_val(py, cred_id)?;
        let user_val = py_to_val(py, user)?;
        self.inner
            .update_user_info(cred_val, user_val)
            .map_err(ctap_err)
    }
}

// ---- NativeFPBioEnrollment ----

#[pyclass]
struct NativeFPBioEnrollment {
    inner: FPBioEnrollment<PyCtapDevice>,
}

#[pymethods]
impl NativeFPBioEnrollment {
    #[new]
    fn new(
        ctap: &NativeCtap2,
        py: Python<'_>,
        protocol_version: u32,
        pin_uv_token: Vec<u8>,
        modality: u32,
    ) -> PyResult<Self> {
        let ctap2 = ctap.make_ctap(py)?;
        let protocol = make_protocol(protocol_version)?;
        let inner = FPBioEnrollment::from_parts(ctap2, protocol, pin_uv_token, modality);
        Ok(Self { inner })
    }

    fn get_fingerprint_sensor_info(
        &mut self,
        py: Python<'_>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let result = with_event_args(event, on_keepalive, || {
            self.inner.get_fingerprint_sensor_info(&mut |_| {}, None)
        })
        .map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    #[pyo3(signature = (timeout=None, event=None, on_keepalive=None))]
    fn enroll_begin(
        &mut self,
        py: Python<'_>,
        timeout: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let (template_id, status, remaining) = with_event_args(event, on_keepalive, || {
            self.inner.enroll_begin(timeout, &mut |_| {}, None)
        })
        .map_err(ctap_err)?;
        Ok(PyTuple::new(
            py,
            [
                PyBytes::new(py, &template_id).into_any(),
                status.into_pyobject(py)?.into_any(),
                remaining.into_pyobject(py)?.into_any(),
            ],
        )?
        .into())
    }

    #[pyo3(signature = (template_id, timeout=None, event=None, on_keepalive=None))]
    fn enroll_capture_next(
        &mut self,
        py: Python<'_>,
        template_id: &[u8],
        timeout: Option<u32>,
        event: Option<PyObject>,
        on_keepalive: Option<PyObject>,
    ) -> PyResult<PyObject> {
        let (status, remaining) = with_event_args(event, on_keepalive, || {
            self.inner
                .enroll_capture_next(template_id, timeout, &mut |_| {}, None)
        })
        .map_err(ctap_err)?;
        Ok(PyTuple::new(
            py,
            [
                status.into_pyobject(py)?.into_any(),
                remaining.into_pyobject(py)?.into_any(),
            ],
        )?
        .into())
    }

    fn enroll_cancel(&mut self) -> PyResult<()> {
        self.inner.enroll_cancel().map_err(ctap_err)
    }

    fn enumerate_enrollments(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let result = self.inner.enumerate_enrollments().map_err(ctap_err)?;
        val_to_pyobj(py, &result)
    }

    fn set_name(&mut self, template_id: &[u8], name: &str) -> PyResult<()> {
        self.inner.set_name(template_id, name).map_err(ctap_err)
    }

    fn remove_enrollment(&mut self, template_id: &[u8]) -> PyResult<()> {
        self.inner.remove_enrollment(template_id).map_err(ctap_err)
    }
}

// ---- NativeLargeBlobs ----

#[pyclass]
struct NativeLargeBlobs {
    inner: LargeBlobs<PyCtapDevice>,
}

#[pymethods]
impl NativeLargeBlobs {
    #[new]
    #[pyo3(signature = (ctap, max_fragment_length, protocol_version=None, pin_uv_token=None))]
    fn new(
        ctap: &NativeCtap2,
        py: Python<'_>,
        max_fragment_length: usize,
        protocol_version: Option<u32>,
        pin_uv_token: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let ctap2 = ctap.make_ctap(py)?;
        let protocol = protocol_version.map(make_protocol).transpose()?;
        let inner = LargeBlobs::from_parts(ctap2, max_fragment_length, protocol, pin_uv_token);
        Ok(Self { inner })
    }

    fn read_blob_array(&mut self, py: Python<'_>) -> PyResult<PyObject> {
        let results = self.inner.read_blob_array().map_err(ctap_err)?;
        let list = PyList::empty(py);
        for v in &results {
            list.append(py_cbor::value_to_py(py, v)?)?;
        }
        Ok(list.into())
    }

    fn write_blob_array(&mut self, py: Python<'_>, blob_array: PyObject) -> PyResult<()> {
        let arr_val = py_to_val(py, blob_array)?;
        let entries = match arr_val {
            Value::Array(a) => a,
            _ => return Err(PyValueError::new_err("Expected list")),
        };
        self.inner.write_blob_array(&entries).map_err(ctap_err)
    }

    fn get_blob(&mut self, py: Python<'_>, large_blob_key: &[u8]) -> PyResult<PyObject> {
        match self.inner.get_blob(large_blob_key).map_err(ctap_err)? {
            Some(data) => Ok(PyBytes::new(py, &data).into()),
            None => Ok(py.None()),
        }
    }

    fn put_blob(&mut self, large_blob_key: &[u8], data: Option<&[u8]>) -> PyResult<()> {
        self.inner.put_blob(large_blob_key, data).map_err(ctap_err)
    }

    fn delete_blob(&mut self, large_blob_key: &[u8]) -> PyResult<()> {
        self.inner.delete_blob(large_blob_key).map_err(ctap_err)
    }
}

// ---- NativeConfig ----

#[pyclass]
struct NativeConfig {
    inner: Config<PyCtapDevice>,
}

#[pymethods]
impl NativeConfig {
    #[new]
    #[pyo3(signature = (ctap, protocol_version=None, pin_uv_token=None))]
    fn new(
        ctap: &NativeCtap2,
        py: Python<'_>,
        protocol_version: Option<u32>,
        pin_uv_token: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let ctap2 = ctap.make_ctap(py)?;
        let protocol = protocol_version.map(make_protocol).transpose()?;
        let inner = Config::from_parts(ctap2, protocol, pin_uv_token);
        Ok(Self { inner })
    }

    fn enable_enterprise_attestation(&mut self) -> PyResult<()> {
        self.inner.enable_enterprise_attestation().map_err(ctap_err)
    }

    fn toggle_always_uv(&mut self) -> PyResult<()> {
        self.inner.toggle_always_uv().map_err(ctap_err)
    }

    #[pyo3(signature = (min_pin_length=None, rp_ids=None, force_change_pin=false))]
    fn set_min_pin_length(
        &mut self,
        min_pin_length: Option<u32>,
        rp_ids: Option<Vec<String>>,
        force_change_pin: bool,
    ) -> PyResult<()> {
        let rp_strs: Option<Vec<&str>> = rp_ids
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect());
        self.inner
            .set_min_pin_length(min_pin_length, rp_strs.as_deref(), force_change_pin)
            .map_err(ctap_err)
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "ctap")?;
    sub.add_class::<NativeCtap1>()?;
    sub.add_class::<NativeCtap2>()?;
    sub.add_class::<NativeClientPin>()?;
    sub.add_class::<NativeCredentialManagement>()?;
    sub.add_class::<NativeFPBioEnrollment>()?;
    sub.add_class::<NativeLargeBlobs>()?;
    sub.add_class::<NativeConfig>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.ctap", &sub)?;

    Ok(())
}
