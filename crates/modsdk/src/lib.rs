#![cfg_attr(not(target_arch = "wasm32"), forbid(unsafe_code))]
#![deny(missing_docs)]
//! Small SDK for capability-aware Agent-Fleet modules.
//!
//! The SDK is safe to use. The only `unsafe` code in the crate is the
//! `wasm32` import/allocator shim, which must turn raw pointers supplied by the
//! host into slices. That shim is compiled only for `wasm32-unknown-unknown`.

pub use modsdk_macros::mod_main;
use serde_json::Value;
use std::sync::Arc;
use thiserror::Error;

/// Errors returned by SDK host wrappers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CapError {
    /// The host denied the requested capability.
    #[error("capability denied: {0}")]
    Denied(String),
    /// The host returned malformed data or failed internally.
    #[error("host error: {0}")]
    Host(String),
}

/// Host-call surface used by [`Ctx`].
///
/// The default implementation calls the ABI imports. Tests can supply another
/// implementation through [`Ctx::with_host`].
pub trait Host: Send + Sync {
    /// Reads a file after the host checks `fs_read`.
    fn read_file(&self, path: &str) -> Result<Vec<u8>, CapError>;
    /// Lists a directory as JSON after the host checks `fs_read`.
    fn read_dir(&self, path: &str) -> Result<Vec<u8>, CapError>;
    /// Returns JSON metadata for a path after the host checks `fs_read`.
    fn stat(&self, path: &str) -> Result<Vec<u8>, CapError>;
    /// Reads a byte range after the host checks `fs_read`.
    fn read_file_range(&self, path: &str, offset: u64, len: usize) -> Result<Vec<u8>, CapError>;
    /// Writes a file after the host checks `fs_write`.
    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), CapError>;
    /// Runs a command after the host checks `exec`.
    fn exec(&self, command: &str, args: &[String]) -> Result<Vec<u8>, CapError>;
    /// Performs an HTTP GET after the host checks `net`.
    fn http_get(&self, url: &str) -> Result<Vec<u8>, CapError>;
    /// Performs an HTTP POST after the host checks `net`.
    fn http_post(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, CapError>;
    /// Appends an artifact to the state SQLite spool after `spool` is checked.
    fn spool_put(&self, path: &str, kind: &str, data: &[u8]) -> Result<i64, CapError>;
    /// Returns host time after the host checks `clock`.
    fn clock_ms(&self) -> Result<u64, CapError>;
    /// Returns host randomness after the host checks `random`.
    fn random(&self, len: usize) -> Result<Vec<u8>, CapError>;
    /// Reads an environment value after the host checks `env`.
    fn env_get(&self, key: &str) -> Result<Option<String>, CapError>;
    /// Sleeps after the host checks `sleep`.
    fn sleep_ms(&self, millis: u64) -> Result<(), CapError>;
    /// Logs one line through the host.
    fn log(&self, message: &str);
}

/// Context passed to a module entry point.
#[derive(Clone)]
pub struct Ctx {
    args: Value,
    host: Arc<dyn Host>,
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Ctx")
            .field("args", &self.args)
            .finish_non_exhaustive()
    }
}

impl Default for Ctx {
    fn default() -> Self {
        Self::new(Value::Object(Default::default()))
    }
}

impl Ctx {
    /// Creates a context from JSON-compatible arguments using the ABI host.
    pub fn new(args: Value) -> Self {
        Self {
            args,
            host: default_host(),
        }
    }

    /// Creates a context with an explicit host implementation.
    pub fn with_host(args: Value, host: Arc<dyn Host>) -> Self {
        Self { args, host }
    }

    /// Parses JSON arguments delivered by `handle`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CapError> {
        let args = if bytes.is_empty() {
            Value::Object(Default::default())
        } else {
            serde_json::from_slice(bytes)
                .map_err(|error| CapError::Host(format!("invalid args JSON: {error}")))?
        };
        Ok(Self::new(args))
    }

    /// Returns the original module arguments.
    pub fn args(&self) -> &Value {
        &self.args
    }

    /// Reads a file through the capability-gated host (`fs_read`).
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, CapError> {
        self.host.read_file(path)
    }

    /// Lists a directory through the host (`fs_read`, ABI 2).
    pub fn read_dir(&self, path: &str) -> Result<Vec<u8>, CapError> {
        self.host.read_dir(path)
    }

    /// Returns path metadata through the host (`fs_read`, ABI 2).
    pub fn stat(&self, path: &str) -> Result<Vec<u8>, CapError> {
        self.host.stat(path)
    }

    /// Reads a byte range through the host (`fs_read`, ABI 2).
    pub fn read_file_range(
        &self,
        path: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, CapError> {
        self.host.read_file_range(path, offset, len)
    }

    /// Writes a file through the capability-gated host (`fs_write`).
    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), CapError> {
        self.host.write_file(path, data)
    }

    /// POSTs a body through the host (`net`, ABI 2).
    pub fn http_post(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, CapError> {
        self.host.http_post(url, body)
    }

    /// Appends an artifact to the client spool (`spool`, ABI 2).
    pub fn spool_put(&self, path: &str, kind: &str, data: &[u8]) -> Result<i64, CapError> {
        self.host.spool_put(path, kind, data)
    }

    /// Runs a command through the capability-gated host (`exec`).
    pub fn exec(&self, command: &str, args: &[String]) -> Result<Vec<u8>, CapError> {
        self.host.exec(command, args)
    }

    /// Performs an HTTP GET through the capability-gated host (`net`).
    pub fn http_get(&self, url: &str) -> Result<Vec<u8>, CapError> {
        self.host.http_get(url)
    }

    /// Returns host time through the capability-gated host (`clock`).
    pub fn clock_ms(&self) -> Result<u64, CapError> {
        self.host.clock_ms()
    }

    /// Returns host randomness through the capability-gated host (`random`).
    pub fn random(&self, len: usize) -> Result<Vec<u8>, CapError> {
        self.host.random(len)
    }

    /// Reads an environment value through the capability-gated host (`env`).
    pub fn env_get(&self, key: &str) -> Result<Option<String>, CapError> {
        self.host.env_get(key)
    }

    /// Sleeps through the capability-gated host (`sleep`).
    pub fn sleep_ms(&self, millis: u64) -> Result<(), CapError> {
        self.host.sleep_ms(millis)
    }

    /// Logs one line through the host.
    pub fn log(&self, message: &str) {
        self.host.log(message);
    }

    /// Emits a successful ABI result whose `stdout` is `stdout`.
    ///
    /// Modules that build findings JSON call this once before returning `Ok`.
    /// Reaching `Ok` without calling it lets the host report an empty success.
    pub fn emit_stdout(&self, stdout: &str) {
        let payload = serde_json::json!({
            "ok": true,
            "stdout": stdout,
            "stderr": "",
            "code": 0,
        });
        emit_json(&payload.to_string());
    }
}

fn default_host() -> Arc<dyn Host> {
    #[cfg(target_arch = "wasm32")]
    {
        Arc::new(abi::AbiHost)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Arc::new(UnavailableHost)
    }
}

/// Host used when the SDK is compiled for a non-wasm target.
#[derive(Debug, Default)]
pub struct UnavailableHost;

impl Host for UnavailableHost {
    fn read_file(&self, _path: &str) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn read_dir(&self, _path: &str) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn stat(&self, _path: &str) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn read_file_range(&self, _path: &str, _offset: u64, _len: usize) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn write_file(&self, _path: &str, _data: &[u8]) -> Result<(), CapError> {
        Err(unavailable())
    }
    fn exec(&self, _command: &str, _args: &[String]) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn http_get(&self, _url: &str) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn http_post(&self, _url: &str, _body: &[u8]) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn spool_put(&self, _path: &str, _kind: &str, _data: &[u8]) -> Result<i64, CapError> {
        Err(unavailable())
    }
    fn clock_ms(&self) -> Result<u64, CapError> {
        Err(unavailable())
    }
    fn random(&self, _len: usize) -> Result<Vec<u8>, CapError> {
        Err(unavailable())
    }
    fn env_get(&self, _key: &str) -> Result<Option<String>, CapError> {
        Err(unavailable())
    }
    fn sleep_ms(&self, _millis: u64) -> Result<(), CapError> {
        Err(unavailable())
    }
    fn log(&self, _message: &str) {}
}

fn unavailable() -> CapError {
    CapError::Host("host calls are only available inside a wasm32 module".into())
}

#[cfg(target_arch = "wasm32")]
#[allow(dead_code)] // ABI declarations are linked one feature at a time.
mod abi {
    use super::{CapError, Host};
    use std::slice;

    const DENIED: i64 = -1;
    const HOST_ERROR: i64 = -2;

    #[link(wasm_import_module = "env")]
    extern "C" {
        fn log(ptr: *const u8, len: i32);
        fn read_file(ptr: *const u8, len: i32) -> i64;
        fn read_dir(ptr: *const u8, len: i32) -> i64;
        fn stat(ptr: *const u8, len: i32) -> i64;
        fn read_file_range(ptr: *const u8, len: i32, offset: i64, want: i64) -> i64;
        fn write_file(path: *const u8, path_len: i32, data: *const u8, data_len: i32) -> i32;
        fn exec(cmd: *const u8, cmd_len: i32, args: *const u8, args_len: i32) -> i64;
        fn http_get(ptr: *const u8, len: i32) -> i64;
        fn http_post(url: *const u8, url_len: i32, body: *const u8, body_len: i32) -> i64;
        fn clock_ms() -> i64;
        fn random(ptr: *mut u8, len: i32) -> i32;
        fn env_get(ptr: *const u8, len: i32) -> i64;
        fn sleep_ms(millis: i64) -> i32;
        fn spool_put(
            path: *const u8,
            path_len: i32,
            kind: *const u8,
            kind_len: i32,
            data: *const u8,
            data_len: i32,
        ) -> i64;
        fn result(ptr: *const u8, len: i32);
    }

    /// Calls the ABI 1 imports.
    #[derive(Debug, Default)]
    pub struct AbiHost;

    fn unpack(name: &str, packed: i64) -> Result<Vec<u8>, CapError> {
        match packed {
            DENIED => Err(CapError::Denied(name.into())),
            HOST_ERROR => Err(CapError::Host(name.into())),
            value if value < 0 => Err(CapError::Host(format!("{name}: code {value}"))),
            0 => Ok(Vec::new()),
            value => {
                let ptr = (value >> 32) as usize;
                let len = (value & 0xffff_ffff) as usize;
                // SAFETY: the host allocated this range in our linear memory
                // immediately before returning it and the guest owns it.
                Ok(unsafe { slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
            }
        }
    }

    fn pack(data: &[u8]) -> (*const u8, i32) {
        (data.as_ptr(), data.len() as i32)
    }

    impl Host for AbiHost {
        #[cfg(feature = "fs-read")]
        fn read_file(&self, path: &str) -> Result<Vec<u8>, CapError> {
            let (ptr, len) = pack(path.as_bytes());
            unpack("fs_read", unsafe { read_file(ptr, len) })
        }
        #[cfg(not(feature = "fs-read"))]
        fn read_file(&self, _path: &str) -> Result<Vec<u8>, CapError> {
            Err(unlinked("fs_read"))
        }
        #[cfg(feature = "fs-dir")]
        fn read_dir(&self, path: &str) -> Result<Vec<u8>, CapError> {
            let (ptr, len) = pack(path.as_bytes());
            unpack("fs_read", unsafe { read_dir(ptr, len) })
        }
        #[cfg(not(feature = "fs-dir"))]
        fn read_dir(&self, _path: &str) -> Result<Vec<u8>, CapError> {
            Err(unlinked("fs_read"))
        }
        #[cfg(feature = "fs-dir")]
        fn stat(&self, path: &str) -> Result<Vec<u8>, CapError> {
            let (ptr, len) = pack(path.as_bytes());
            unpack("fs_read", unsafe { stat(ptr, len) })
        }
        #[cfg(not(feature = "fs-dir"))]
        fn stat(&self, _path: &str) -> Result<Vec<u8>, CapError> {
            Err(unlinked("fs_read"))
        }
        #[cfg(feature = "fs-range")]
        fn read_file_range(
            &self,
            path: &str,
            offset: u64,
            len: usize,
        ) -> Result<Vec<u8>, CapError> {
            let (ptr, path_len) = pack(path.as_bytes());
            unpack("fs_read", unsafe {
                read_file_range(ptr, path_len, offset as i64, len as i64)
            })
        }
        #[cfg(not(feature = "fs-range"))]
        fn read_file_range(
            &self,
            _path: &str,
            _offset: u64,
            _len: usize,
        ) -> Result<Vec<u8>, CapError> {
            Err(unlinked("fs_read"))
        }

        #[cfg(feature = "fs-write")]
        fn write_file(&self, path: &str, data: &[u8]) -> Result<(), CapError> {
            let (path_ptr, path_len) = pack(path.as_bytes());
            let (data_ptr, data_len) = pack(data);
            match unsafe { write_file(path_ptr, path_len, data_ptr, data_len) } {
                0 => Ok(()),
                DENIED_CODE => Err(CapError::Denied("fs_write".into())),
                _ => Err(CapError::Host("fs_write".into())),
            }
        }
        #[cfg(not(feature = "fs-write"))]
        fn write_file(&self, _path: &str, _data: &[u8]) -> Result<(), CapError> {
            Err(unlinked("fs_write"))
        }

        #[cfg(feature = "exec")]
        fn exec(&self, command: &str, args: &[String]) -> Result<Vec<u8>, CapError> {
            let (command_ptr, command_len) = pack(command.as_bytes());
            let encoded = serde_json::to_vec(args)
                .map_err(|error| CapError::Host(format!("exec args: {error}")))?;
            let (args_ptr, args_len) = pack(&encoded);
            unpack("exec", unsafe {
                exec(command_ptr, command_len, args_ptr, args_len)
            })
        }
        #[cfg(not(feature = "exec"))]
        fn exec(&self, _command: &str, _args: &[String]) -> Result<Vec<u8>, CapError> {
            Err(unlinked("exec"))
        }

        #[cfg(feature = "net")]
        fn http_get(&self, url: &str) -> Result<Vec<u8>, CapError> {
            let (ptr, len) = pack(url.as_bytes());
            unpack("net", unsafe { http_get(ptr, len) })
        }
        #[cfg(not(feature = "net"))]
        fn http_get(&self, _url: &str) -> Result<Vec<u8>, CapError> {
            Err(unlinked("net"))
        }
        #[cfg(feature = "net-post")]
        fn http_post(&self, url: &str, body: &[u8]) -> Result<Vec<u8>, CapError> {
            let (url_ptr, url_len) = pack(url.as_bytes());
            let (body_ptr, body_len) = pack(body);
            unpack("net", unsafe {
                http_post(url_ptr, url_len, body_ptr, body_len)
            })
        }
        #[cfg(not(feature = "net-post"))]
        fn http_post(&self, _url: &str, _body: &[u8]) -> Result<Vec<u8>, CapError> {
            Err(unlinked("net"))
        }
        #[cfg(feature = "spool")]
        fn spool_put(&self, path: &str, kind: &str, data: &[u8]) -> Result<i64, CapError> {
            let (path_ptr, path_len) = pack(path.as_bytes());
            let (kind_ptr, kind_len) = pack(kind.as_bytes());
            let (data_ptr, data_len) = pack(data);
            match unsafe { spool_put(path_ptr, path_len, kind_ptr, kind_len, data_ptr, data_len) } {
                DENIED => Err(CapError::Denied("spool".into())),
                HOST_ERROR => Err(CapError::Host("spool".into())),
                id => Ok(id),
            }
        }
        #[cfg(not(feature = "spool"))]
        fn spool_put(&self, _path: &str, _kind: &str, _data: &[u8]) -> Result<i64, CapError> {
            Err(unlinked("spool"))
        }

        #[cfg(feature = "clock")]
        fn clock_ms(&self) -> Result<u64, CapError> {
            match unsafe { clock_ms() } {
                value if value >= 0 => Ok(value as u64),
                DENIED => Err(CapError::Denied("clock".into())),
                _ => Err(CapError::Host("clock".into())),
            }
        }
        #[cfg(not(feature = "clock"))]
        fn clock_ms(&self) -> Result<u64, CapError> {
            Err(unlinked("clock"))
        }

        #[cfg(feature = "random")]
        fn random(&self, len: usize) -> Result<Vec<u8>, CapError> {
            let mut bytes = vec![0_u8; len];
            match unsafe { random(bytes.as_mut_ptr(), bytes.len() as i32) } {
                0 => Ok(bytes),
                DENIED_CODE => Err(CapError::Denied("random".into())),
                _ => Err(CapError::Host("random".into())),
            }
        }
        #[cfg(not(feature = "random"))]
        fn random(&self, _len: usize) -> Result<Vec<u8>, CapError> {
            Err(unlinked("random"))
        }

        #[cfg(feature = "env")]
        fn env_get(&self, key: &str) -> Result<Option<String>, CapError> {
            let (ptr, len) = pack(key.as_bytes());
            match unsafe { env_get(ptr, len) } {
                0 => Ok(None),
                value => unpack("env", value)
                    .map(|bytes| Some(String::from_utf8_lossy(&bytes).into_owned())),
            }
        }
        #[cfg(not(feature = "env"))]
        fn env_get(&self, _key: &str) -> Result<Option<String>, CapError> {
            Err(unlinked("env"))
        }

        #[cfg(feature = "sleep")]
        fn sleep_ms(&self, millis: u64) -> Result<(), CapError> {
            match unsafe { sleep_ms(millis.min(5000) as i64) } {
                0 => Ok(()),
                DENIED_CODE => Err(CapError::Denied("sleep".into())),
                _ => Err(CapError::Host("sleep".into())),
            }
        }
        #[cfg(not(feature = "sleep"))]
        fn sleep_ms(&self, _millis: u64) -> Result<(), CapError> {
            Err(unlinked("sleep"))
        }

        #[cfg(feature = "log")]
        fn log(&self, message: &str) {
            let (ptr, len) = pack(message.as_bytes());
            unsafe { log(ptr, len) };
        }
        #[cfg(not(feature = "log"))]
        fn log(&self, _message: &str) {}
    }

    fn unlinked(capability: &str) -> CapError {
        CapError::Host(format!(
            "{capability} is not linked; enable the matching modsdk feature"
        ))
    }

    const DENIED_CODE: i32 = -1;

    /// Reports a JSON payload through the ABI `result` import.
    pub fn emit_result(payload: &str) {
        let (ptr, len) = pack(payload.as_bytes());
        unsafe { result(ptr, len) };
    }

    /// Returns the argument slice delivered to `handle`.
    ///
    /// # Safety
    /// `ptr` and `len` must describe a valid range in guest memory.
    pub unsafe fn args_slice(ptr: i32, len: i32) -> &'static [u8] {
        if len == 0 {
            return &[];
        }
        slice::from_raw_parts(ptr as usize as *const u8, len as usize)
    }
}

/// Allocates `len` zeroed bytes in guest memory and returns their pointer.
#[cfg_attr(target_arch = "wasm32", export_name = "alloc")]
pub extern "C" fn __alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let boxed = vec![0_u8; len as usize].into_boxed_slice();
        Box::into_raw(boxed) as *mut u8 as i32
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = len;
        0
    }
}

/// Frees a previous [`__alloc`] allocation.
#[cfg_attr(target_arch = "wasm32", export_name = "dealloc")]
pub extern "C" fn __dealloc(ptr: i32, len: i32) {
    if ptr == 0 || len <= 0 {
        return;
    }
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: the pair came from `__alloc`, which used a boxed slice of
        // exactly this length.
        unsafe {
            let slice = std::ptr::slice_from_raw_parts_mut(ptr as *mut u8, len as usize);
            drop(Box::from_raw(slice));
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
    }
}

/// Emits a successful module result with no output.
pub fn __result_ok() {
    emit_json("{\"ok\":true,\"stdout\":\"\",\"stderr\":\"\",\"code\":0}");
}

/// Emits a failed module result carrying `message`.
pub fn __result_error(message: &str) {
    let payload = serde_json::json!({
        "ok": false,
        "stdout": "",
        "stderr": message,
        "code": 1,
    });
    emit_json(&payload.to_string());
}

fn emit_json(payload: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        abi::emit_result(payload);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = payload;
    }
}

/// Builds a context from the `handle` argument range.
///
/// The host guarantees that `ptr` and `len` describe a valid range in guest
/// memory for the duration of the call, so this helper is safe to call from
/// generated `handle` shims.
pub fn __ctx_from_args(ptr: i32, len: i32) -> Result<Ctx, CapError> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: the host passes the range it just allocated for `handle`.
        Ctx::from_json(unsafe { abi::args_slice(ptr, len) })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (ptr, len);
        Ok(Ctx::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockHost {
        deny: bool,
    }

    impl Host for MockHost {
        fn read_file(&self, _path: &str) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("fs_read".into()));
            }
            Ok(b"contents".to_vec())
        }
        fn read_dir(&self, _path: &str) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("fs_read".into()));
            }
            Ok(b"[]".to_vec())
        }
        fn stat(&self, _path: &str) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("fs_read".into()));
            }
            Ok(b"{}".to_vec())
        }
        fn read_file_range(&self, _path: &str, _o: u64, _l: usize) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("fs_read".into()));
            }
            Ok(b"range".to_vec())
        }
        fn write_file(&self, _path: &str, _data: &[u8]) -> Result<(), CapError> {
            if self.deny {
                return Err(CapError::Denied("fs_write".into()));
            }
            Ok(())
        }
        fn exec(&self, _command: &str, _args: &[String]) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("exec".into()));
            }
            Ok(b"ok".to_vec())
        }
        fn http_get(&self, _url: &str) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("net".into()));
            }
            Ok(b"response".to_vec())
        }
        fn http_post(&self, _url: &str, _body: &[u8]) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("net".into()));
            }
            Ok(b"posted".to_vec())
        }
        fn spool_put(&self, _path: &str, _kind: &str, _data: &[u8]) -> Result<i64, CapError> {
            if self.deny {
                return Err(CapError::Denied("spool".into()));
            }
            Ok(1)
        }
        fn clock_ms(&self) -> Result<u64, CapError> {
            if self.deny {
                return Err(CapError::Denied("clock".into()));
            }
            Ok(42)
        }
        fn random(&self, len: usize) -> Result<Vec<u8>, CapError> {
            if self.deny {
                return Err(CapError::Denied("random".into()));
            }
            Ok(vec![7; len])
        }
        fn env_get(&self, _key: &str) -> Result<Option<String>, CapError> {
            if self.deny {
                return Err(CapError::Denied("env".into()));
            }
            Ok(Some("value".into()))
        }
        fn sleep_ms(&self, _millis: u64) -> Result<(), CapError> {
            if self.deny {
                return Err(CapError::Denied("sleep".into()));
            }
            Ok(())
        }
        fn log(&self, _message: &str) {}
    }

    #[test]
    fn args_parse_and_every_method_denies_and_succeeds() {
        let args = serde_json::json!({"alpha": 1});
        let allowed = Ctx::with_host(args.clone(), Arc::new(MockHost { deny: false }));
        assert_eq!(allowed.args(), &args);
        assert_eq!(allowed.read_file("/a").expect("read"), b"contents");
        assert_eq!(allowed.read_dir("/a").expect("list"), b"[]");
        assert_eq!(allowed.stat("/a").expect("stat"), b"{}");
        assert_eq!(
            allowed.read_file_range("/a", 0, 4).expect("range"),
            b"range"
        );
        allowed.write_file("/a", b"x").expect("write");
        assert_eq!(
            allowed.http_post("https://x", b"y").expect("post"),
            b"posted"
        );
        assert_eq!(allowed.spool_put("/a", "file", b"x").expect("spool"), 1);
        assert_eq!(allowed.exec("/bin/true", &[]).expect("exec"), b"ok");
        assert_eq!(allowed.http_get("https://x").expect("get"), b"response");
        assert_eq!(allowed.clock_ms().expect("clock"), 42);
        assert_eq!(allowed.random(3).expect("random"), vec![7, 7, 7]);
        assert_eq!(allowed.env_get("K").expect("env"), Some("value".into()));
        allowed.sleep_ms(1).expect("sleep");
        allowed.log("line");

        let denied = Ctx::with_host(args, Arc::new(MockHost { deny: true }));
        assert!(matches!(denied.read_file("/a"), Err(CapError::Denied(_))));
        assert!(matches!(denied.read_dir("/a"), Err(CapError::Denied(_))));
        assert!(matches!(denied.stat("/a"), Err(CapError::Denied(_))));
        assert!(matches!(
            denied.read_file_range("/a", 0, 4),
            Err(CapError::Denied(_))
        ));
        assert!(matches!(
            denied.http_post("https://x", b"y"),
            Err(CapError::Denied(_))
        ));
        assert!(matches!(
            denied.spool_put("/a", "file", b"x"),
            Err(CapError::Denied(_))
        ));
        assert!(matches!(
            denied.write_file("/a", b"x"),
            Err(CapError::Denied(_))
        ));
        assert!(matches!(
            denied.exec("/bin/true", &[]),
            Err(CapError::Denied(_))
        ));
        assert!(matches!(
            denied.http_get("https://x"),
            Err(CapError::Denied(_))
        ));
        assert!(matches!(denied.clock_ms(), Err(CapError::Denied(_))));
        assert!(matches!(denied.random(1), Err(CapError::Denied(_))));
        assert!(matches!(denied.env_get("K"), Err(CapError::Denied(_))));
        assert!(matches!(denied.sleep_ms(1), Err(CapError::Denied(_))));
    }
}
