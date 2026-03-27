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

use fido2::utils;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString};

#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let hash = utils::sha256(data);
    PyBytes::new(py, &hash)
}

#[pyfunction]
fn hmac_sha256<'py>(py: Python<'py>, key: &[u8], data: &[u8]) -> Bound<'py, PyBytes> {
    let mac = utils::hmac_sha256(key, data);
    PyBytes::new(py, &mac)
}

#[pyfunction]
fn websafe_encode(data: &[u8]) -> String {
    utils::websafe_encode(data)
}

#[pyfunction]
fn websafe_decode<'py>(py: Python<'py>, data: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let s: String = if data.is_instance_of::<PyString>() {
        data.extract()?
    } else {
        // Accept bytes-like objects, decode as ASCII
        let bytes: Vec<u8> = data.extract()?;
        String::from_utf8(bytes)
            .map_err(|e| PyValueError::new_err(format!("Invalid ASCII: {e}")))?
    };
    let decoded = utils::websafe_decode(&s).map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &decoded))
}

#[pyfunction]
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    utils::bytes_eq(a, b)
}

#[pyfunction]
fn aes_gcm_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        utils::aes_gcm_encrypt(key, nonce, plaintext, aad).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result))
}

#[pyfunction]
fn aes_gcm_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result =
        utils::aes_gcm_decrypt(key, nonce, ciphertext, aad).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &result))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "utils")?;
    sub.add_function(wrap_pyfunction!(sha256, &sub)?)?;
    sub.add_function(wrap_pyfunction!(hmac_sha256, &sub)?)?;
    sub.add_function(wrap_pyfunction!(websafe_encode, &sub)?)?;
    sub.add_function(wrap_pyfunction!(websafe_decode, &sub)?)?;
    sub.add_function(wrap_pyfunction!(bytes_eq, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_gcm_encrypt, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_gcm_decrypt, &sub)?)?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.utils", &sub)?;

    Ok(())
}
