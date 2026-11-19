//! OS resource ceilings and process-group control.
//!
//! This is the only module in `agentd` that is allowed to use `unsafe`, and it
//! is limited to four libc calls: `setrlimit` for the address-space ceiling,
//! `kill` with a negative pid for process-group termination during shutdown,
//! `kill` with a positive pid to forward supervisor shutdown, and `statvfs` for
//! the fetch disk precheck. See `docs/UNSAFE.md`.
#![allow(unsafe_code)]

use std::io;

/// Applies an address-space ceiling to the current process.
///
/// On non-Unix platforms the limit is reported by the caller and this function
/// is a no-op; Windows uses the supervisor's job-object integration point.
#[cfg(unix)]
pub fn apply_memory_limit(bytes: u64) -> io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: bytes as libc::rlim_t,
        rlim_max: bytes as libc::rlim_t,
    };
    // SAFETY: `limit` is a valid, initialized `rlimit` for the duration of the
    // call, and `RLIMIT_AS` is a valid resource identifier.
    let result = unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// See [`apply_memory_limit`]; non-Unix builds have no portable shell-level hook.
#[cfg(not(unix))]
pub fn apply_memory_limit(_bytes: u64) -> io::Result<()> {
    Ok(())
}

/// Terminates a process group started by a handler.
///
/// The group id is the pid of the leader because handlers spawn children with
/// `process_group(0)`.
#[cfg(unix)]
pub fn kill_process_group(pgid: u32) {
    // SAFETY: signal delivery is inherently process-global; a negative pid asks
    // the kernel to target the group led by `pgid`. Failure is intentionally
    // ignored because the group may already have exited.
    let _ = unsafe { libc::kill(-(pgid as libc::pid_t), libc::SIGKILL) };
}

/// See [`kill_process_group`]; non-Unix builds do not register groups.
#[cfg(not(unix))]
pub fn kill_process_group(_pgid: u32) {}

/// Asks a supervised worker to shut down so it can drain before exiting.
///
/// The supervisor forwards the signal it received instead of dying first and
/// orphaning the worker.
#[cfg(unix)]
pub fn terminate_process(pid: u32) {
    // SAFETY: a positive pid targets exactly one process; a pid that has already
    // exited only makes the call fail, which is intentionally ignored.
    let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
}

/// See [`terminate_process`]; Windows has no catchable SIGTERM, so ask
/// `taskkill` to close the worker's console tree.
#[cfg(not(unix))]
pub fn terminate_process(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T"])
        .status();
}

/// Returns the free bytes available on the filesystem containing `path`.
#[cfg(unix)]
pub fn free_disk_bytes(path: &std::path::Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a nul byte"))?;
    // SAFETY: `stat` is zero-initialized and only written by `statvfs`; the path
    // is a valid nul-terminated string for the duration of the call.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
            Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// See [`free_disk_bytes`]; non-Unix builds report an unknown amount.
#[cfg(not(unix))]
pub fn free_disk_bytes(_path: &std::path::Path) -> io::Result<u64> {
    Ok(u64::MAX)
}
