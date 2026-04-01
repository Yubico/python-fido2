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
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyInt, PyList, PyMemoryView, PyString};

/// Convert a Python object to a cbor::Value.
pub fn py_to_value(obj: &Bound<'_, PyAny>) -> PyResult<cbor::Value> {
    // Check bool before int (bool is a subclass of int in Python)
    if obj.is_instance_of::<PyBool>() {
        return Ok(cbor::Value::Bool(obj.extract::<bool>()?));
    }
    if obj.is_instance_of::<PyInt>() {
        return Ok(cbor::Value::Int(obj.extract::<i64>()?));
    }
    if obj.is_instance_of::<PyString>() {
        return Ok(cbor::Value::Text(obj.extract::<String>()?));
    }
    if obj.is_instance_of::<PyBytes>()
        || obj.is_instance_of::<pyo3::types::PyByteArray>()
        || obj.is_instance_of::<PyMemoryView>()
    {
        return Ok(cbor::Value::Bytes(obj.extract::<Vec<u8>>()?));
    }
    // Check dict/Mapping before list/Sequence
    if obj.downcast::<PyDict>().is_ok() || obj.hasattr("items")? {
        let items: Bound<'_, PyAny> = obj.call_method0("items")?;
        let iter = items.try_iter()?;
        let mut entries = Vec::new();
        for item in iter {
            let item = item?;
            let key = item.get_item(0)?;
            let val = item.get_item(1)?;
            entries.push((py_to_value(&key)?, py_to_value(&val)?));
        }
        return Ok(cbor::Value::Map(entries));
    }
    if obj.downcast::<PyList>().is_ok() || obj.is_instance_of::<pyo3::types::PyTuple>() {
        let iter = obj.try_iter()?;
        let mut items = Vec::new();
        for item in iter {
            items.push(py_to_value(&item?)?);
        }
        return Ok(cbor::Value::Array(items));
    }
    Err(PyValueError::new_err(format!(
        "Unsupported CBOR type: {}",
        obj.get_type().name()?
    )))
}

/// Convert a cbor::Value to a Python object.
pub fn value_to_py<'py>(py: Python<'py>, value: &cbor::Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        cbor::Value::Int(n) => Ok(n.into_pyobject(py)?.into_any()),
        cbor::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
        cbor::Value::Text(s) => Ok(s.into_pyobject(py)?.into_any()),
        cbor::Value::Bytes(b) => Ok(PyBytes::new(py, b).into_any()),
        cbor::Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(value_to_py(py, item)?)?;
            }
            Ok(list.into_any())
        }
        cbor::Value::Map(entries) => {
            let dict = PyDict::new(py);
            for (k, v) in entries {
                dict.set_item(value_to_py(py, k)?, value_to_py(py, v)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

fn cbor_err(e: cbor::CborError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// Encode a Python value to CBOR bytes.
#[pyfunction]
fn encode<'py>(py: Python<'py>, data: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let value = py_to_value(data)?;
    let encoded = value.encode();
    Ok(PyBytes::new(py, &encoded))
}

/// Decode CBOR bytes to a Python value.
#[pyfunction]
fn decode<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let value = cbor::decode(data).map_err(cbor_err)?;
    value_to_py(py, &value)
}

/// Decode a CBOR value from the start of a byte string.
/// Returns (value, remaining_bytes).
#[pyfunction]
fn decode_from<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyBytes>,
) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyBytes>)> {
    let bytes = data.as_bytes();
    let (value, rest) = cbor::decode_from(bytes).map_err(cbor_err)?;
    let py_value = value_to_py(py, &value)?;
    let py_rest = PyBytes::new(py, rest);
    Ok((py_value, py_rest))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "cbor")?;
    sub.add_function(wrap_pyfunction!(encode, &sub)?)?;
    sub.add_function(wrap_pyfunction!(decode, &sub)?)?;
    sub.add_function(wrap_pyfunction!(decode_from, &sub)?)?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.cbor", &sub)?;

    Ok(())
}
