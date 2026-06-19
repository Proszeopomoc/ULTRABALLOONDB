use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use ultraballoondb_cabi::{
    ubdb_abi_version_v1, ubdb_protocol_config_init_v1, ubdb_protocol_version_v1,
    ubdb_session_create_v1, ubdb_session_destroy_v1, ubdb_session_max_frame_bytes_v1,
    ubdb_session_process_frame_v1, UbdbBackendCallbacksV1, UbdbBackendHealthV1,
    UbdbBytesViewV1, UbdbProtocolConfigV1, UbdbSessionHandleV1, UBDB_ABI_VERSION_V1,
    UBDB_STATUS_BACKEND, UBDB_STATUS_BUFFER_TOO_SMALL, UBDB_STATUS_CLOSED,
    UBDB_STATUS_INVALID_ARGUMENT, UBDB_STATUS_IO, UBDB_STATUS_NULL_POINTER,
    UBDB_STATUS_OK, UBDB_STATUS_PANIC, UBDB_STATUS_PROTOCOL,
};
use ultraballoondb_daemon::{
    encode_hello, Frame, FrameKind, DEFAULT_IO_TIMEOUT_MILLIS, DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_MAX_READ_PAYLOAD_BYTES, DEFAULT_MAX_REQUESTS_PER_CONNECTION,
    DEFAULT_MAX_WRITE_PAYLOAD_BYTES, PROTOCOL_VERSION,
};

pub const VERSION: &str = "V00R3D4_PYO3_R01";

struct PythonContext {
    backend: Py<PyAny>,
    response: Vec<u8>,
    in_callback: bool,
    max_output_bytes: usize,
}

fn status_error(status: i32, operation: &str) -> PyErr {
    let message = format!("{operation} failed with UltraBalloonDB status {status}");
    match status {
        UBDB_STATUS_INVALID_ARGUMENT | UBDB_STATUS_NULL_POINTER | UBDB_STATUS_BUFFER_TOO_SMALL => {
            PyValueError::new_err(message)
        }
        UBDB_STATUS_PROTOCOL => PyValueError::new_err(message),
        UBDB_STATUS_BACKEND | UBDB_STATUS_CLOSED | UBDB_STATUS_IO | UBDB_STATUS_PANIC => {
            PyRuntimeError::new_err(message)
        }
        _ => PyRuntimeError::new_err(message),
    }
}

unsafe fn context_mut<'a>(context: *mut c_void) -> Option<&'a mut PythonContext> {
    if context.is_null() {
        None
    } else {
        Some(&mut *(context as *mut PythonContext))
    }
}

fn guarded_callback<F>(operation: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(status) => status,
        Err(_) => UBDB_STATUS_PANIC,
    }
}

unsafe extern "C" fn python_health_callback(
    context: *mut c_void,
    out_health: *mut UbdbBackendHealthV1,
) -> i32 {
    guarded_callback(|| {
        if out_health.is_null() {
            return UBDB_STATUS_NULL_POINTER;
        }
        let context = match unsafe { context_mut(context) } {
            Some(value) => value,
            None => return UBDB_STATUS_NULL_POINTER,
        };
        if context.in_callback {
            return UBDB_STATUS_BACKEND;
        }
        context.in_callback = true;
        let result = Python::with_gil(|py| {
            context
                .backend
                .bind(py)
                .call_method0("health")
                .and_then(|value| value.extract::<(bool, bool, u64)>())
        });
        context.in_callback = false;
        let (healthy, read_only, generation) = match result {
            Ok(value) => value,
            Err(_) => return UBDB_STATUS_BACKEND,
        };
        unsafe {
            (*out_health).struct_size = size_of::<UbdbBackendHealthV1>() as u32;
            (*out_health).abi_version = UBDB_ABI_VERSION_V1;
            (*out_health).healthy = u8::from(healthy);
            (*out_health).read_only = u8::from(read_only);
            (*out_health).reserved = [0; 6];
            (*out_health).generation = generation;
        }
        UBDB_STATUS_OK
    })
}

unsafe fn python_execute_callback(
    context: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out_response: *mut UbdbBytesViewV1,
    method: &str,
) -> i32 {
    guarded_callback(|| {
        if out_response.is_null() || (request_len != 0 && request_ptr.is_null()) {
            return UBDB_STATUS_NULL_POINTER;
        }
        let context = match unsafe { context_mut(context) } {
            Some(value) => value,
            None => return UBDB_STATUS_NULL_POINTER,
        };
        if context.in_callback {
            return UBDB_STATUS_BACKEND;
        }
        let request = if request_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(request_ptr, request_len) }
        };
        context.in_callback = true;
        let result = Python::with_gil(|py| {
            let argument = PyBytes::new(py, request);
            context
                .backend
                .bind(py)
                .call_method1(method, (argument,))
                .and_then(|value| value.extract::<Vec<u8>>())
        });
        context.in_callback = false;
        let response = match result {
            Ok(value) => value,
            Err(_) => return UBDB_STATUS_BACKEND,
        };
        if response.len() > context.max_output_bytes {
            return UBDB_STATUS_BACKEND;
        }
        context.response = response;
        unsafe {
            (*out_response).ptr = if context.response.is_empty() {
                ptr::null()
            } else {
                context.response.as_ptr()
            };
            (*out_response).len = context.response.len();
        }
        UBDB_STATUS_OK
    })
}

unsafe extern "C" fn python_read_callback(
    context: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out_response: *mut UbdbBytesViewV1,
) -> i32 {
    unsafe {
        python_execute_callback(
            context,
            request_ptr,
            request_len,
            out_response,
            "execute_read",
        )
    }
}

unsafe extern "C" fn python_write_callback(
    context: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out_response: *mut UbdbBytesViewV1,
) -> i32 {
    unsafe {
        python_execute_callback(
            context,
            request_ptr,
            request_len,
            out_response,
            "execute_write",
        )
    }
}

#[pyclass(unsendable, name = "Session")]
pub struct PythonSession {
    handle: *mut UbdbSessionHandleV1,
    _context: Box<PythonContext>,
    max_frame_bytes: usize,
}

impl PythonSession {
    fn destroy_inner(&mut self) -> PyResult<()> {
        if self.handle.is_null() {
            return Ok(());
        }
        let status = ubdb_session_destroy_v1(self.handle);
        if status != UBDB_STATUS_OK {
            return Err(status_error(status, "session destroy"));
        }
        self.handle = ptr::null_mut();
        Ok(())
    }
}

impl Drop for PythonSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = ubdb_session_destroy_v1(self.handle);
            self.handle = ptr::null_mut();
        }
    }
}

#[pymethods]
impl PythonSession {
    #[new]
    #[pyo3(signature = (
        backend,
        server_nonce=1,
        max_frame_bytes=DEFAULT_MAX_FRAME_BYTES,
        max_requests_per_connection=DEFAULT_MAX_REQUESTS_PER_CONNECTION,
        max_read_payload_bytes=DEFAULT_MAX_READ_PAYLOAD_BYTES,
        max_write_payload_bytes=DEFAULT_MAX_WRITE_PAYLOAD_BYTES,
        io_timeout_millis=DEFAULT_IO_TIMEOUT_MILLIS,
        loopback_only=true
    ))]
    fn new(
        backend: Py<PyAny>,
        server_nonce: u64,
        max_frame_bytes: u32,
        max_requests_per_connection: u32,
        max_read_payload_bytes: u32,
        max_write_payload_bytes: u32,
        io_timeout_millis: u64,
        loopback_only: bool,
    ) -> PyResult<Self> {
        let mut config = UbdbProtocolConfigV1::default();
        let status = ubdb_protocol_config_init_v1(&mut config);
        if status != UBDB_STATUS_OK {
            return Err(status_error(status, "protocol config init"));
        }
        config.max_frame_bytes = max_frame_bytes;
        config.max_requests_per_connection = max_requests_per_connection;
        config.max_read_payload_bytes = max_read_payload_bytes;
        config.max_write_payload_bytes = max_write_payload_bytes;
        config.io_timeout_millis = io_timeout_millis;
        config.loopback_only = u8::from(loopback_only);
        config.reserved = [0; 7];

        let mut context = Box::new(PythonContext {
            backend,
            response: Vec::new(),
            in_callback: false,
            max_output_bytes: max_frame_bytes as usize,
        });
        let callbacks = UbdbBackendCallbacksV1 {
            struct_size: size_of::<UbdbBackendCallbacksV1>() as u32,
            abi_version: UBDB_ABI_VERSION_V1,
            context: (&mut *context as *mut PythonContext).cast::<c_void>(),
            health: Some(python_health_callback),
            execute_read: Some(python_read_callback),
            execute_write: Some(python_write_callback),
        };
        let mut handle = ptr::null_mut();
        let status = ubdb_session_create_v1(&config, &callbacks, server_nonce, &mut handle);
        if status != UBDB_STATUS_OK {
            return Err(status_error(status, "session create"));
        }
        if handle.is_null() {
            return Err(PyRuntimeError::new_err(
                "session create returned success with a null handle",
            ));
        }
        let mut actual_max_frame_bytes = 0u32;
        let status = ubdb_session_max_frame_bytes_v1(handle, &mut actual_max_frame_bytes);
        if status != UBDB_STATUS_OK {
            let _ = ubdb_session_destroy_v1(handle);
            return Err(status_error(status, "session max frame query"));
        }
        Ok(Self {
            handle,
            _context: context,
            max_frame_bytes: actual_max_frame_bytes as usize,
        })
    }

    fn process_frame<'py>(
        &mut self,
        py: Python<'py>,
        request: &[u8],
    ) -> PyResult<Py<PyBytes>> {
        if self.handle.is_null() {
            return Err(PyRuntimeError::new_err("session is destroyed"));
        }
        let mut response = vec![0u8; self.max_frame_bytes];
        let mut response_len = 0usize;
        let status = ubdb_session_process_frame_v1(
            self.handle,
            request.as_ptr(),
            request.len(),
            response.as_mut_ptr(),
            response.len(),
            &mut response_len,
        );
        if status != UBDB_STATUS_OK {
            return Err(status_error(status, "session process_frame"));
        }
        if response_len > response.len() {
            return Err(PyRuntimeError::new_err(
                "C ABI returned a response length outside the caller-owned buffer",
            ));
        }
        response.truncate(response_len);
        Ok(PyBytes::new(py, &response).unbind())
    }

    fn destroy(&mut self) -> PyResult<()> {
        self.destroy_inner()
    }

    #[getter]
    fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    #[getter]
    fn destroyed(&self) -> bool {
        self.handle.is_null()
    }

    fn __repr__(&self) -> String {
        format!(
            "Session(max_frame_bytes={}, destroyed={})",
            self.max_frame_bytes,
            self.handle.is_null()
        )
    }
}

fn encode_frame_bytes(
    kind: u16,
    request_id: u64,
    payload: &[u8],
    max_frame_bytes: u32,
) -> Result<Vec<u8>, String> {
    let kind = FrameKind::from_u16(kind).map_err(|error| error.to_string())?;
    Frame::new(kind, request_id, payload.to_vec())
        .encode(max_frame_bytes)
        .map_err(|error| error.to_string())
}

#[pyfunction]
#[pyo3(signature = (kind, request_id, payload, max_frame_bytes=DEFAULT_MAX_FRAME_BYTES))]
fn encode_frame<'py>(
    py: Python<'py>,
    kind: u16,
    request_id: u64,
    payload: &[u8],
    max_frame_bytes: u32,
) -> PyResult<Py<PyBytes>> {
    let bytes = encode_frame_bytes(kind, request_id, payload, max_frame_bytes)
        .map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}

#[pyfunction]
#[pyo3(signature = (frame, max_frame_bytes=DEFAULT_MAX_FRAME_BYTES))]
fn decode_frame<'py>(
    py: Python<'py>,
    frame: &[u8],
    max_frame_bytes: u32,
) -> PyResult<(u16, u16, u64, Py<PyBytes>)> {
    let decoded = Frame::decode(frame, max_frame_bytes).map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok((
        decoded.kind as u16,
        decoded.flags,
        decoded.request_id,
        PyBytes::new(py, &decoded.payload).unbind(),
    ))
}

#[pyfunction]
fn encode_hello_payload<'py>(
    py: Python<'py>,
    min_version: u16,
    max_version: u16,
    client_max_frame_bytes: u32,
    client_nonce: u64,
) -> Py<PyBytes> {
    PyBytes::new(
        py,
        &encode_hello(
            min_version,
            max_version,
            client_max_frame_bytes,
            client_nonce,
        ),
    )
    .unbind()
}

#[pyfunction]
fn abi_version() -> u32 {
    ubdb_abi_version_v1()
}

#[pyfunction]
fn protocol_version() -> u16 {
    ubdb_protocol_version_v1()
}

#[pymodule]
fn ultraballoondb_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PythonSession>()?;
    module.add_function(wrap_pyfunction!(encode_frame, module)?)?;
    module.add_function(wrap_pyfunction!(decode_frame, module)?)?;
    module.add_function(wrap_pyfunction!(encode_hello_payload, module)?)?;
    module.add_function(wrap_pyfunction!(abi_version, module)?)?;
    module.add_function(wrap_pyfunction!(protocol_version, module)?)?;
    module.add("VERSION", VERSION)?;
    module.add("ABI_VERSION", UBDB_ABI_VERSION_V1)?;
    module.add("PROTOCOL_VERSION", PROTOCOL_VERSION)?;
    module.add("KIND_HELLO", FrameKind::Hello as u16)?;
    module.add("KIND_PING", FrameKind::Ping as u16)?;
    module.add("KIND_HEALTH", FrameKind::Health as u16)?;
    module.add("KIND_CAPABILITIES", FrameKind::Capabilities as u16)?;
    module.add("KIND_READ", FrameKind::Read as u16)?;
    module.add("KIND_WRITE", FrameKind::Write as u16)?;
    module.add("KIND_CLOSE", FrameKind::Close as u16)?;
    module.add("KIND_HELLO_ACK", FrameKind::HelloAck as u16)?;
    module.add("KIND_PONG", FrameKind::Pong as u16)?;
    module.add("KIND_HEALTH_RESULT", FrameKind::HealthResult as u16)?;
    module.add("KIND_CAPABILITIES_RESULT", FrameKind::CapabilitiesResult as u16)?;
    module.add("KIND_RESULT", FrameKind::Result as u16)?;
    module.add("KIND_ERROR", FrameKind::Error as u16)?;
    module.add("KIND_CLOSE_ACK", FrameKind::CloseAck as u16)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d3_and_d4_versions_are_bound() {
        assert_eq!(ubdb_abi_version_v1(), 1);
        assert_eq!(ubdb_protocol_version_v1(), 1);
        assert_eq!(UBDB_ABI_VERSION_V1, 1);
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn deterministic_frame_helper_roundtrip() {
        let encoded = encode_frame_bytes(FrameKind::Ping as u16, 7, b"abc", 4096).unwrap();
        let decoded = Frame::decode(&encoded, 4096).unwrap();
        assert_eq!(decoded.kind, FrameKind::Ping);
        assert_eq!(decoded.request_id, 7);
        assert_eq!(decoded.payload, b"abc");
    }
}
