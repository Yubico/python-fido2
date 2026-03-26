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

use std::sync::Mutex;

use fido2::transport::ctaphid;
use pyo3::exceptions::PyOSError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn ctap_err(e: ctaphid::CtapHidTransportError) -> PyErr {
    PyOSError::new_err(e.to_string())
}

#[pyclass]
#[derive(Clone)]
pub struct HidDescriptor {
    #[pyo3(get)]
    pub path: String,
    #[pyo3(get)]
    pub vid: u16,
    #[pyo3(get)]
    pub pid: u16,
    #[pyo3(get)]
    pub product_name: Option<String>,
    #[pyo3(get)]
    pub serial_number: Option<String>,
    #[pyo3(get)]
    pub report_size_in: usize,
    #[pyo3(get)]
    pub report_size_out: usize,
}

#[pyfunction]
fn list_descriptors() -> PyResult<Vec<HidDescriptor>> {
    ctaphid::list_devices()
        .map(|devs| {
            devs.into_iter()
                .map(|d| HidDescriptor {
                    path: d.path,
                    vid: d.vid,
                    pid: d.pid,
                    product_name: d.product_name,
                    serial_number: d.serial_number,
                    report_size_in: d.report_size_in,
                    report_size_out: d.report_size_out,
                })
                .collect()
        })
        .map_err(ctap_err)
}

/// Native CTAP HID connection wrapping the Rust transport.
///
/// Uses a Mutex internally so the connection can be safely used across Python threads.
#[pyclass]
pub struct CtapHidConnection {
    inner: Mutex<Option<ctaphid::CtapHidConnection>>,
    packet_size: usize,
    device_version: (u8, u8, u8),
    capabilities: u8,
}

impl CtapHidConnection {
    fn with_conn<F, R>(&self, f: F) -> PyResult<R>
    where
        F: FnOnce(&ctaphid::CtapHidConnection) -> PyResult<R>,
    {
        let guard = self.inner.lock().map_err(|_| PyOSError::new_err("lock poisoned"))?;
        let conn = guard
            .as_ref()
            .ok_or_else(|| PyOSError::new_err("Connection is closed"))?;
        f(conn)
    }
}

#[pymethods]
impl CtapHidConnection {
    #[new]
    fn new(descriptor: &HidDescriptor) -> PyResult<Self> {
        let info = ctaphid::CtapHidDeviceInfo {
            path: descriptor.path.clone(),
            vid: descriptor.vid,
            pid: descriptor.pid,
            product_name: descriptor.product_name.clone(),
            serial_number: descriptor.serial_number.clone(),
            report_size_in: descriptor.report_size_in,
            report_size_out: descriptor.report_size_out,
        };
        let conn = ctaphid::CtapHidConnection::open(&info).map_err(ctap_err)?;
        let device_version = conn.device_version();
        let capabilities = conn.capabilities().raw();
        Ok(Self {
            inner: Mutex::new(Some(conn)),
            packet_size: descriptor.report_size_in,
            device_version,
            capabilities,
        })
    }

    fn write_packet(&self, data: &[u8]) -> PyResult<()> {
        let _ = data;
        Err(PyOSError::new_err(
            "write_packet not supported on native connection; use call() instead",
        ))
    }

    fn read_packet<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let _ = py;
        Err(PyOSError::new_err(
            "read_packet not supported on native connection; use call() instead",
        ))
    }

    /// Send a CTAP HID command and receive the response.
    fn call<'py>(&self, py: Python<'py>, cmd: u8, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let response = self.with_conn(|conn| conn.call(cmd, data).map_err(ctap_err))?;
        Ok(PyBytes::new(py, &response))
    }

    #[getter]
    fn device_version(&self) -> (u8, u8, u8) {
        self.device_version
    }

    #[getter]
    fn capabilities(&self) -> u8 {
        self.capabilities
    }

    #[getter]
    fn packet_size(&self) -> usize {
        self.packet_size
    }

    fn close(&self) -> PyResult<()> {
        let mut guard = self.inner.lock().map_err(|_| PyOSError::new_err("lock poisoned"))?;
        if let Some(mut conn) = guard.take() {
            conn.close();
        }
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_val: Option<&Bound<'_, PyAny>>,
        _exc_tb: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.close()
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let sub = PyModule::new(m.py(), "hid")?;
    sub.add_function(wrap_pyfunction!(list_descriptors, &sub)?)?;
    sub.add_class::<HidDescriptor>()?;
    sub.add_class::<CtapHidConnection>()?;
    m.add_submodule(&sub)?;

    let sys = m.py().import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("_fido2_native.hid", &sub)?;

    Ok(())
}
