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

use fido2::cose::{CoseError, CoseKey};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::py_cbor;

fn cose_err(e: CoseError) -> PyErr {
    match e {
        CoseError::VerificationFailed => {
            // Import InvalidSignature from cryptography.exceptions at runtime
            Python::with_gil(|py| {
                match py.import("cryptography.exceptions") {
                    Ok(m) => match m.getattr("InvalidSignature") {
                        Ok(exc) => PyErr::from_value(
                            exc.call1(("Signature verification failed",))
                                .unwrap_or_else(|_| exc.clone()),
                        ),
                        Err(_) => PyValueError::new_err("Signature verification failed"),
                    },
                    Err(_) => PyValueError::new_err("Signature verification failed"),
                }
            })
        }
        other => PyValueError::new_err(other.to_string()),
    }
}

/// Build a CoseKey from a Python dict with integer keys.
fn dict_to_cose_key(dict: &Bound<'_, PyAny>) -> PyResult<CoseKey> {
    let mut params = BTreeMap::new();
    let items = dict.call_method0("items")?;
    let iter = items.try_iter()?;
    for item in iter {
        let item: Bound<'_, PyAny> = item?;
        let key: i64 = item.get_item(0)?.extract()?;
        let value = py_cbor::py_to_value(&item.get_item(1)?)?;
        params.insert(key, value);
    }
    Ok(CoseKey::from_map(params))
}

/// Verify a signature using a COSE key (provided as a dict).
///
/// Raises InvalidSignature on verification failure,
/// ValueError on invalid key data or unsupported algorithm.
#[pyfunction]
fn verify(key: &Bound<'_, PyAny>, message: &[u8], signature: &[u8]) -> PyResult<()> {
    let cose_key = dict_to_cose_key(key)?;
    cose_key.verify(message, signature).map_err(cose_err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "cose")?;
    sub.add_function(wrap_pyfunction!(verify, &sub)?)?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.cose", &sub)?;

    Ok(())
}
