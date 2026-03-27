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

use fido2::pin;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyTuple};

fn pin_err(e: pin::PinError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Perform ECDH P-256 key agreement with a peer's public key.
/// Returns (public_key_x, public_key_y, shared_secret) as bytes.
#[pyfunction]
fn ecdh_p256<'py>(py: Python<'py>, peer_x: &[u8], peer_y: &[u8]) -> PyResult<Bound<'py, PyTuple>> {
    let result = pin::ecdh_p256(peer_x, peer_y).map_err(pin_err)?;
    let x = PyBytes::new(py, &result.public_key_x);
    let y = PyBytes::new(py, &result.public_key_y);
    let secret = PyBytes::new(py, &result.shared_secret);
    PyTuple::new(py, [x.into_any(), y.into_any(), secret.into_any()])
}

/// General AES-CBC decrypt with a provided IV.
#[pyfunction]
fn aes_cbc_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = pin::aes_cbc_decrypt(key, iv, ciphertext).map_err(pin_err)?;
    Ok(PyBytes::new(py, &result))
}

/// AES-CBC encrypt with zero IV (PIN protocol V1).
#[pyfunction]
fn aes_cbc_encrypt_v1<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = pin::aes_cbc_encrypt_v1(key, plaintext).map_err(pin_err)?;
    Ok(PyBytes::new(py, &result))
}

/// AES-CBC decrypt with zero IV (PIN protocol V1).
#[pyfunction]
fn aes_cbc_decrypt_v1<'py>(
    py: Python<'py>,
    key: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = pin::aes_cbc_decrypt_v1(key, ciphertext).map_err(pin_err)?;
    Ok(PyBytes::new(py, &result))
}

/// AES-256-CBC encrypt with random IV (PIN protocol V2).
/// Returns IV + ciphertext.
#[pyfunction]
fn aes_cbc_encrypt_v2<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = pin::aes_cbc_encrypt_v2(key, plaintext).map_err(pin_err)?;
    Ok(PyBytes::new(py, &result))
}

/// AES-256-CBC decrypt (PIN protocol V2).
/// Expects IV (16 bytes) prepended to ciphertext.
#[pyfunction]
fn aes_cbc_decrypt_v2<'py>(
    py: Python<'py>,
    key: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let result = pin::aes_cbc_decrypt_v2(key, data).map_err(pin_err)?;
    Ok(PyBytes::new(py, &result))
}

/// HKDF-SHA256 key derivation.
#[pyfunction]
fn hkdf_sha256<'py>(
    py: Python<'py>,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
) -> Bound<'py, PyBytes> {
    let result = pin::hkdf_sha256(salt, ikm, info, length);
    PyBytes::new(py, &result)
}

/// PIN protocol V1 KDF: SHA-256 of the shared secret.
#[pyfunction]
fn kdf_v1<'py>(py: Python<'py>, z: &[u8]) -> Bound<'py, PyBytes> {
    let result = pin::kdf_v1(z);
    PyBytes::new(py, &result)
}

/// PIN protocol V2 KDF: HKDF-SHA256 to derive HMAC key + AES key (64 bytes).
#[pyfunction]
fn kdf_v2<'py>(py: Python<'py>, z: &[u8]) -> Bound<'py, PyBytes> {
    let result = pin::kdf_v2(z);
    PyBytes::new(py, &result)
}

#[pyclass]
struct NativePinProtocol {
    protocol: pin::PinProtocol,
}

#[pymethods]
impl NativePinProtocol {
    #[new]
    fn new(version: u32) -> PyResult<Self> {
        let protocol = match version {
            1 => pin::PinProtocol::V1,
            2 => pin::PinProtocol::V2,
            _ => return Err(PyValueError::new_err("Unsupported protocol version")),
        };
        Ok(Self { protocol })
    }

    #[getter]
    fn version(&self) -> u32 {
        self.protocol.version()
    }

    /// Perform ECDH key agreement.
    /// Returns (key_agreement_dict, shared_secret_bytes).
    fn encapsulate<'py>(
        &self,
        py: Python<'py>,
        peer_x: &[u8],
        peer_y: &[u8],
    ) -> PyResult<Bound<'py, PyTuple>> {
        let (ka, shared) = self.protocol.encapsulate(peer_x, peer_y).map_err(pin_err)?;

        // Build key_agreement as a Python dict: {1: 2, 3: -25, -1: 1, -2: x, -3: y}
        let ka_dict = PyDict::new(py);
        ka_dict.set_item(1i32, 2i32)?;
        ka_dict.set_item(3i32, -25i32)?;
        ka_dict.set_item(-1i32, 1i32)?;
        ka_dict.set_item(-2i32, PyBytes::new(py, &ka.x))?;
        ka_dict.set_item(-3i32, PyBytes::new(py, &ka.y))?;

        let shared_bytes = PyBytes::new(py, &shared);
        PyTuple::new(py, [ka_dict.into_any(), shared_bytes.into_any()])
    }

    fn encrypt<'py>(
        &self,
        py: Python<'py>,
        key: &[u8],
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let result = self.protocol.encrypt(key, plaintext).map_err(pin_err)?;
        Ok(PyBytes::new(py, &result))
    }

    fn decrypt<'py>(
        &self,
        py: Python<'py>,
        key: &[u8],
        ciphertext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let result = self.protocol.decrypt(key, ciphertext).map_err(pin_err)?;
        Ok(PyBytes::new(py, &result))
    }

    fn authenticate<'py>(
        &self,
        py: Python<'py>,
        key: &[u8],
        message: &[u8],
    ) -> Bound<'py, PyBytes> {
        let result = self.protocol.authenticate(key, message);
        PyBytes::new(py, &result)
    }

    fn validate_token<'py>(&self, py: Python<'py>, token: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let result = self.protocol.validate_token(token).map_err(pin_err)?;
        Ok(PyBytes::new(py, &result))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "pin")?;
    sub.add_function(wrap_pyfunction!(ecdh_p256, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_cbc_decrypt, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_cbc_encrypt_v1, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_cbc_decrypt_v1, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_cbc_encrypt_v2, &sub)?)?;
    sub.add_function(wrap_pyfunction!(aes_cbc_decrypt_v2, &sub)?)?;
    sub.add_function(wrap_pyfunction!(hkdf_sha256, &sub)?)?;
    sub.add_function(wrap_pyfunction!(kdf_v1, &sub)?)?;
    sub.add_function(wrap_pyfunction!(kdf_v2, &sub)?)?;
    sub.add_class::<NativePinProtocol>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.pin", &sub)?;

    Ok(())
}
