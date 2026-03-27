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

use fido2::x509::{self, Certificate};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::py_cbor::value_to_py;

#[pyclass(name = "Certificate")]
struct PyCertificate {
    inner: Certificate,
}

#[pymethods]
impl PyCertificate {
    #[new]
    fn new(der: &[u8]) -> PyResult<Self> {
        let inner = Certificate::from_der(der).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Extract the public key as a COSE key dict.
    fn public_key_as_cose(&self, py: Python<'_>, alg: i64) -> PyResult<PyObject> {
        let cose_key = self
            .inner
            .public_key_as_cose(alg)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let cbor_map = cose_key.to_cbor();
        Ok(value_to_py(py, &cbor_map)?.into())
    }

    /// Get a subject attribute value by OID string.
    fn subject_string(&self, oid: &str) -> Option<String> {
        self.inner.subject_string(oid)
    }

    /// Check if the subject has no attributes.
    fn subject_is_empty(&self) -> bool {
        self.inner.subject_is_empty()
    }

    /// Get the certificate version (0=v1, 1=v2, 2=v3).
    fn version(&self) -> u8 {
        self.inner.version()
    }

    /// Get an extension's raw value by OID string.
    /// Returns (critical, raw_value) or None.
    fn extension_value<'py>(
        &self,
        py: Python<'py>,
        oid: &str,
    ) -> Option<(bool, Bound<'py, PyBytes>)> {
        let (critical, value) = self.inner.extension_value(oid)?;
        Some((critical, PyBytes::new(py, &value)))
    }

    /// Check BasicConstraints CA flag. Returns None if extension missing.
    fn basic_constraints_ca(&self) -> Option<bool> {
        self.inner.basic_constraints_ca()
    }

    /// Check if ExtendedKeyUsage contains a specific OID.
    fn extended_key_usage_contains(&self, oid: &str) -> bool {
        self.inner.extended_key_usage_contains(oid)
    }

    /// Check if SubjectAlternativeName extension is present.
    fn has_subject_alternative_name(&self) -> bool {
        self.inner.has_subject_alternative_name()
    }

    /// Get the DER-encoded issuer name.
    fn issuer_der<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let der = self
            .inner
            .issuer_der()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &der))
    }

    /// Get the DER-encoded subject name.
    fn subject_der<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let der = self
            .inner
            .subject_der()
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(PyBytes::new(py, &der))
    }

    /// Compute the Subject Key Identifier (SHA-1 of public key bytes).
    fn subject_key_identifier<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.subject_key_identifier())
    }
}

/// Verify an X.509 certificate chain.
/// chain[0] is the leaf, chain[last] is the root.
#[pyfunction]
fn verify_x509_chain(chain: Vec<Vec<u8>>) -> PyResult<()> {
    x509::verify_x509_chain(&chain).map_err(|e| PyValueError::new_err(e.to_string()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "x509")?;
    sub.add_class::<PyCertificate>()?;
    sub.add_function(wrap_pyfunction!(verify_x509_chain, &sub)?)?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.x509", &sub)?;

    Ok(())
}
