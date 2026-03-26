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

use fido2::client;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

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

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "client")?;
    sub.add_class::<ClientDataCollector>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.client", &sub)?;

    Ok(())
}
