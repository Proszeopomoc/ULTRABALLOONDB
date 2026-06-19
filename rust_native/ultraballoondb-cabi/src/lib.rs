use std::ffi::c_void;
use std::mem::size_of;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use ultraballoondb_daemon::{
    BackendHealth, DaemonBackend, DaemonError, DaemonSession, Frame, ProtocolConfig,
    DEFAULT_IO_TIMEOUT_MILLIS, DEFAULT_MAX_FRAME_BYTES, DEFAULT_MAX_READ_PAYLOAD_BYTES,
    DEFAULT_MAX_REQUESTS_PER_CONNECTION, DEFAULT_MAX_WRITE_PAYLOAD_BYTES, PROTOCOL_VERSION,
};

pub const VERSION: &str = "V00R3D3_C_ABI_R02";
pub const UBDB_ABI_VERSION_V1: u32 = 1;

pub const UBDB_STATUS_OK: i32 = 0;
pub const UBDB_STATUS_INVALID_ARGUMENT: i32 = 1;
pub const UBDB_STATUS_NULL_POINTER: i32 = 2;
pub const UBDB_STATUS_BUFFER_TOO_SMALL: i32 = 3;
pub const UBDB_STATUS_PROTOCOL: i32 = 4;
pub const UBDB_STATUS_BACKEND: i32 = 5;
pub const UBDB_STATUS_CLOSED: i32 = 6;
pub const UBDB_STATUS_IO: i32 = 7;
pub const UBDB_STATUS_PANIC: i32 = 255;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UbdbProtocolConfigV1 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub max_frame_bytes: u32,
    pub max_requests_per_connection: u32,
    pub max_read_payload_bytes: u32,
    pub max_write_payload_bytes: u32,
    pub io_timeout_millis: u64,
    pub loopback_only: u8,
    pub reserved: [u8; 7],
}

impl Default for UbdbProtocolConfigV1 {
    fn default() -> Self {
        Self {
            struct_size: size_of::<Self>() as u32,
            abi_version: UBDB_ABI_VERSION_V1,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_requests_per_connection: DEFAULT_MAX_REQUESTS_PER_CONNECTION,
            max_read_payload_bytes: DEFAULT_MAX_READ_PAYLOAD_BYTES,
            max_write_payload_bytes: DEFAULT_MAX_WRITE_PAYLOAD_BYTES,
            io_timeout_millis: DEFAULT_IO_TIMEOUT_MILLIS,
            loopback_only: 1,
            reserved: [0; 7],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UbdbBackendHealthV1 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub healthy: u8,
    pub read_only: u8,
    pub reserved: [u8; 6],
    pub generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UbdbBytesViewV1 {
    pub ptr: *const u8,
    pub len: usize,
}

impl Default for UbdbBytesViewV1 {
    fn default() -> Self { Self { ptr: ptr::null(), len: 0 } }
}

pub type UbdbHealthCallbackV1 = unsafe extern "C" fn(
    context: *mut c_void,
    out_health: *mut UbdbBackendHealthV1,
) -> i32;

pub type UbdbExecuteCallbackV1 = unsafe extern "C" fn(
    context: *mut c_void,
    request_ptr: *const u8,
    request_len: usize,
    out_response: *mut UbdbBytesViewV1,
) -> i32;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UbdbBackendCallbacksV1 {
    pub struct_size: u32,
    pub abi_version: u32,
    pub context: *mut c_void,
    pub health: Option<UbdbHealthCallbackV1>,
    pub execute_read: Option<UbdbExecuteCallbackV1>,
    pub execute_write: Option<UbdbExecuteCallbackV1>,
}

#[repr(C)]
pub struct UbdbSessionHandleV1 { _private: [u8; 0] }

#[derive(Clone, Copy)]
struct CallbackBackend {
    context: *mut c_void,
    health: UbdbHealthCallbackV1,
    execute_read: UbdbExecuteCallbackV1,
    execute_write: UbdbExecuteCallbackV1,
    max_output_bytes: usize,
}

impl CallbackBackend {
    fn execute(
        &self,
        callback: UbdbExecuteCallbackV1,
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let mut view = UbdbBytesViewV1::default();
        let code = unsafe {
            callback(
                self.context,
                if request.is_empty() { ptr::null() } else { request.as_ptr() },
                request.len(),
                &mut view,
            )
        };
        if code != UBDB_STATUS_OK {
            return Err(format!("C backend callback returned status {code}"));
        }
        if view.len > self.max_output_bytes {
            return Err("C backend callback response exceeds configured frame bound".to_string());
        }
        if view.len == 0 { return Ok(Vec::new()); }
        if view.ptr.is_null() {
            return Err("C backend callback returned null response with non-zero length".to_string());
        }
        let bytes = unsafe { slice::from_raw_parts(view.ptr, view.len) };
        Ok(bytes.to_vec())
    }
}

impl DaemonBackend for CallbackBackend {
    fn health(&self) -> BackendHealth {
        let mut health = UbdbBackendHealthV1 {
            struct_size: size_of::<UbdbBackendHealthV1>() as u32,
            abi_version: UBDB_ABI_VERSION_V1,
            ..UbdbBackendHealthV1::default()
        };
        let code = unsafe { (self.health)(self.context, &mut health) };
        if code != UBDB_STATUS_OK
            || health.struct_size != size_of::<UbdbBackendHealthV1>() as u32
            || health.abi_version != UBDB_ABI_VERSION_V1
            || health.reserved != [0; 6]
            || health.healthy > 1
            || health.read_only > 1
        {
            return BackendHealth { healthy: false, read_only: true, generation: 0 };
        }
        BackendHealth {
            healthy: health.healthy == 1,
            read_only: health.read_only == 1,
            generation: health.generation,
        }
    }

    fn execute_read(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.execute(self.execute_read, request)
    }

    fn execute_write(&mut self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        self.execute(self.execute_write, request)
    }
}

struct SessionBox {
    max_frame_bytes: u32,
    session: DaemonSession<CallbackBackend>,
}

fn map_error(error: DaemonError) -> i32 {
    match error {
        DaemonError::Invalid(_) => UBDB_STATUS_INVALID_ARGUMENT,
        DaemonError::Protocol(_) => UBDB_STATUS_PROTOCOL,
        DaemonError::Backend(_) => UBDB_STATUS_BACKEND,
        DaemonError::Closed => UBDB_STATUS_CLOSED,
        DaemonError::Io(_) => UBDB_STATUS_IO,
    }
}

fn guarded<F>(operation: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(status) => status,
        Err(_) => UBDB_STATUS_PANIC,
    }
}

unsafe fn session_mut<'a>(handle: *mut UbdbSessionHandleV1) -> std::result::Result<&'a mut SessionBox, i32> {
    if handle.is_null() { return Err(UBDB_STATUS_NULL_POINTER); }
    Ok(&mut *(handle as *mut SessionBox))
}

fn convert_config(config: &UbdbProtocolConfigV1) -> std::result::Result<ProtocolConfig, i32> {
    if config.struct_size != size_of::<UbdbProtocolConfigV1>() as u32
        || config.abi_version != UBDB_ABI_VERSION_V1
        || config.loopback_only > 1
        || config.reserved != [0; 7]
    {
        return Err(UBDB_STATUS_INVALID_ARGUMENT);
    }
    let converted = ProtocolConfig {
        max_frame_bytes: config.max_frame_bytes,
        max_requests_per_connection: config.max_requests_per_connection,
        max_read_payload_bytes: config.max_read_payload_bytes,
        max_write_payload_bytes: config.max_write_payload_bytes,
        io_timeout_millis: config.io_timeout_millis,
        loopback_only: config.loopback_only == 1,
    };
    converted.validate().map_err(map_error)?;
    Ok(converted)
}

#[no_mangle]
pub extern "C" fn ubdb_abi_version_v1() -> u32 { UBDB_ABI_VERSION_V1 }

#[no_mangle]
pub extern "C" fn ubdb_protocol_version_v1() -> u16 { PROTOCOL_VERSION }

#[no_mangle]
pub extern "C" fn ubdb_protocol_config_init_v1(out_config: *mut UbdbProtocolConfigV1) -> i32 {
    guarded(|| {
        if out_config.is_null() { return UBDB_STATUS_NULL_POINTER; }
        unsafe { ptr::write(out_config, UbdbProtocolConfigV1::default()); }
        UBDB_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn ubdb_session_create_v1(
    config: *const UbdbProtocolConfigV1,
    backend: *const UbdbBackendCallbacksV1,
    server_nonce: u64,
    out_handle: *mut *mut UbdbSessionHandleV1,
) -> i32 {
    guarded(|| {
        if out_handle.is_null() { return UBDB_STATUS_NULL_POINTER; }
        unsafe { *out_handle = ptr::null_mut(); }
        if config.is_null() || backend.is_null() { return UBDB_STATUS_NULL_POINTER; }
        if server_nonce == 0 { return UBDB_STATUS_INVALID_ARGUMENT; }
        let config_ref = unsafe { &*config };
        let backend_ref = unsafe { &*backend };
        if backend_ref.struct_size != size_of::<UbdbBackendCallbacksV1>() as u32
            || backend_ref.abi_version != UBDB_ABI_VERSION_V1
        {
            return UBDB_STATUS_INVALID_ARGUMENT;
        }
        let health = match backend_ref.health { Some(value) => value, None => return UBDB_STATUS_INVALID_ARGUMENT };
        let execute_read = match backend_ref.execute_read { Some(value) => value, None => return UBDB_STATUS_INVALID_ARGUMENT };
        let execute_write = match backend_ref.execute_write { Some(value) => value, None => return UBDB_STATUS_INVALID_ARGUMENT };
        let converted = match convert_config(config_ref) { Ok(value) => value, Err(status) => return status };
        let max_frame_bytes = converted.max_frame_bytes;
        let callback_backend = CallbackBackend {
            context: backend_ref.context,
            health,
            execute_read,
            execute_write,
            max_output_bytes: max_frame_bytes.saturating_sub(64) as usize,
        };
        let session = match DaemonSession::new(converted, callback_backend, server_nonce) {
            Ok(value) => value,
            Err(error) => return map_error(error),
        };
        let boxed = Box::new(SessionBox { max_frame_bytes, session });
        unsafe { *out_handle = Box::into_raw(boxed) as *mut UbdbSessionHandleV1; }
        UBDB_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn ubdb_session_max_frame_bytes_v1(
    handle: *mut UbdbSessionHandleV1,
    out_max_frame_bytes: *mut u32,
) -> i32 {
    guarded(|| {
        if out_max_frame_bytes.is_null() { return UBDB_STATUS_NULL_POINTER; }
        let session = match unsafe { session_mut(handle) } { Ok(value) => value, Err(status) => return status };
        unsafe { *out_max_frame_bytes = session.max_frame_bytes; }
        UBDB_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn ubdb_session_process_frame_v1(
    handle: *mut UbdbSessionHandleV1,
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_capacity: usize,
    out_response_len: *mut usize,
) -> i32 {
    guarded(|| {
        if out_response_len.is_null() { return UBDB_STATUS_NULL_POINTER; }
        unsafe { *out_response_len = 0; }
        if request_ptr.is_null() || response_ptr.is_null() { return UBDB_STATUS_NULL_POINTER; }
        let session = match unsafe { session_mut(handle) } { Ok(value) => value, Err(status) => return status };
        if response_capacity < session.max_frame_bytes as usize {
            unsafe { *out_response_len = session.max_frame_bytes as usize; }
            return UBDB_STATUS_BUFFER_TOO_SMALL;
        }
        if request_len > session.max_frame_bytes as usize { return UBDB_STATUS_PROTOCOL; }
        let request_bytes = unsafe { slice::from_raw_parts(request_ptr, request_len) };
        let request = match Frame::decode(request_bytes, session.max_frame_bytes) {
            Ok(value) => value,
            Err(error) => return map_error(error),
        };
        let response = match session.session.handle(request) {
            Ok(value) => value,
            Err(error) => return map_error(error),
        };
        let encoded = match response.encode(session.max_frame_bytes) {
            Ok(value) => value,
            Err(error) => return map_error(error),
        };
        if encoded.len() > response_capacity { return UBDB_STATUS_PANIC; }
        unsafe {
            ptr::copy_nonoverlapping(encoded.as_ptr(), response_ptr, encoded.len());
            *out_response_len = encoded.len();
        }
        UBDB_STATUS_OK
    })
}

#[no_mangle]
pub extern "C" fn ubdb_session_destroy_v1(handle: *mut UbdbSessionHandleV1) -> i32 {
    guarded(|| {
        if handle.is_null() { return UBDB_STATUS_NULL_POINTER; }
        unsafe { drop(Box::from_raw(handle as *mut SessionBox)); }
        UBDB_STATUS_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ultraballoondb_daemon::{encode_hello, FrameKind};

    unsafe extern "C" fn health(_: *mut c_void, out: *mut UbdbBackendHealthV1) -> i32 {
        if out.is_null() { return UBDB_STATUS_NULL_POINTER; }
        (*out).struct_size = size_of::<UbdbBackendHealthV1>() as u32;
        (*out).abi_version = UBDB_ABI_VERSION_V1;
        (*out).healthy = 1;
        (*out).read_only = 0;
        (*out).reserved = [0; 6];
        (*out).generation = 7;
        UBDB_STATUS_OK
    }

    static READ_RESPONSE: &[u8] = b"CABI_READ";
    static WRITE_RESPONSE: &[u8] = b"CABI_WRITE";

    unsafe extern "C" fn read(_: *mut c_void, _: *const u8, _: usize, out: *mut UbdbBytesViewV1) -> i32 {
        if out.is_null() { return UBDB_STATUS_NULL_POINTER; }
        (*out).ptr = READ_RESPONSE.as_ptr();
        (*out).len = READ_RESPONSE.len();
        UBDB_STATUS_OK
    }
    unsafe extern "C" fn write(_: *mut c_void, _: *const u8, _: usize, out: *mut UbdbBytesViewV1) -> i32 {
        if out.is_null() { return UBDB_STATUS_NULL_POINTER; }
        (*out).ptr = WRITE_RESPONSE.as_ptr();
        (*out).len = WRITE_RESPONSE.len();
        UBDB_STATUS_OK
    }

    fn callbacks() -> UbdbBackendCallbacksV1 {
        UbdbBackendCallbacksV1 {
            struct_size: size_of::<UbdbBackendCallbacksV1>() as u32,
            abi_version: UBDB_ABI_VERSION_V1,
            context: ptr::null_mut(),
            health: Some(health),
            execute_read: Some(read),
            execute_write: Some(write),
        }
    }

    #[test]
    fn frozen_fixed_struct_sizes() {
        assert_eq!(size_of::<UbdbProtocolConfigV1>(), 40);
        assert_eq!(size_of::<UbdbBackendHealthV1>(), 24);
    }

    #[test]
    fn rejects_payload_limits_larger_than_frame_capacity() {
        let mut config = UbdbProtocolConfigV1::default();
        assert_eq!(ubdb_protocol_config_init_v1(&mut config), UBDB_STATUS_OK);
        config.max_frame_bytes = 4096;
        let callbacks = callbacks();
        let mut handle = ptr::null_mut();
        assert_eq!(
            ubdb_session_create_v1(&config, &callbacks, 9, &mut handle),
            UBDB_STATUS_INVALID_ARGUMENT
        );
        assert!(handle.is_null());
    }

    #[test]
    fn lifecycle_and_caller_owned_buffer_contract() {
        let mut config = UbdbProtocolConfigV1::default();
        assert_eq!(ubdb_protocol_config_init_v1(&mut config), UBDB_STATUS_OK);
        config.max_frame_bytes = 4096;
        config.max_read_payload_bytes = 1024;
        config.max_write_payload_bytes = 1024;
        let callbacks = callbacks();
        let mut handle = ptr::null_mut();
        assert_eq!(ubdb_session_create_v1(&config, &callbacks, 9, &mut handle), UBDB_STATUS_OK);
        assert!(!handle.is_null());

        let hello = Frame::new(FrameKind::Hello, 1, encode_hello(1, 1, 4096, 3)).encode(4096).unwrap();
        let mut tiny = [0u8; 8];
        let mut required = 0usize;
        assert_eq!(
            ubdb_session_process_frame_v1(handle, hello.as_ptr(), hello.len(), tiny.as_mut_ptr(), tiny.len(), &mut required),
            UBDB_STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(required, 4096);

        let mut out = vec![0u8; 4096];
        let mut out_len = 0usize;
        assert_eq!(
            ubdb_session_process_frame_v1(handle, hello.as_ptr(), hello.len(), out.as_mut_ptr(), out.len(), &mut out_len),
            UBDB_STATUS_OK
        );
        assert_eq!(Frame::decode(&out[..out_len], 4096).unwrap().kind, FrameKind::HelloAck);
        assert_eq!(ubdb_session_destroy_v1(handle), UBDB_STATUS_OK);
    }
}
