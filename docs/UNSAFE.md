# Unsafe code policy

The workspace defaults to `#![forbid(unsafe_code)]` on every crate. `agentd` is
the single exception and lowers its lint from `forbid` to `deny`, so exactly one
module can opt back in:

```rust
// crates/agentd/src/limits.rs
#![allow(unsafe_code)]
```

Lint levels (verified by `cargo clippy --workspace --all-targets -- -D warnings`):

| Crate | Lint |
| --- | --- |
| `msgfmt`, `transport`, `relayd`, `adminctl`, `db`, `modsdk-macros` | `forbid(unsafe_code)` |
| `modsdk` | `forbid(unsafe_code)` on non-wasm targets (`cfg_attr`) |
| `integration-tests` | `forbid(unsafe_code)` |
| `agentd` binary (`main.rs`) | `forbid(unsafe_code)` |
| `agentd` library (`lib.rs`) | `deny(unsafe_code)`, with `#[allow(unsafe_code)]` on `limits.rs` only |
| `stealer` library | `deny(unsafe_code)`, with `#[allow(unsafe_code)]` on the Windows DPAPI shim only |

## Why `limits.rs` exists

Rust's standard library has no stable API for process address-space limits,
process signalling, or filesystem statistics. The daemon needs all four uses:

1. **Memory ceiling (P50).** `production::apply_resource_policy` calls
   `limits::apply_memory_limit`, which wraps `setrlimit(RLIMIT_AS, ...)` with a
   default of 256 MiB (`AGENT_FLEET_MEMORY_LIMIT` overrides it). A runaway mod or
   shell cannot take the host's memory with it.
2. **Kill by process group (P52).** Shell tasks and Wasm `exec` calls spawn with
   `process_group(0)`. `handlers::kill_active_process_groups` calls
   `limits::kill_process_group`, which sends `SIGKILL` to the negative pid so
   children of a shell cannot outlive the drain window.
3. **Supervisor shutdown forwarding.** `main` forwards SIGTERM/SIGINT received by
   the supervisor to the worker pid with `limits::terminate_process`, so the
   worker drains instead of being orphaned; the supervisor then exits zero.
4. **Fetch disk precheck.** `handlers::fetch` checks
   `limits::free_disk_bytes` (`statvfs`) before streaming a download and requires
   twice the expected size to be available.

## Safety arguments

Each `unsafe` block carries a `SAFETY:` comment. The invariants are:

- `setrlimit`: the `rlimit` value is initialized for the duration of the call and
  `RLIMIT_AS` is a valid resource. Failure is returned as `io::Error`; startup
  fails rather than silently running without a ceiling.
- `kill`: signal delivery is process-global by definition. A negative pid targets
  the group led by the handler's child. Failure is ignored because the group may
  already have exited; it is never used for memory safety or authorization.
- `statvfs`: the `statvfs` struct is zero-initialized and only written by the
  kernel call; the path is a valid NUL-terminated `CString` held for the call.
  A failure is surfaced to the fetch handler, which refuses the download.

`stealer`'s Windows-only DPAPI call is the second exception: `CryptUnprotectData`
fills an OS-owned buffer that is copied and freed with `LocalFree`; both pointers
come from the call contract and no application data is dereferenced. No other
crate or module may add `unsafe` without updating this document and this table.

## Platform notes

- On Unix the four calls are compiled and used.
- On non-Unix targets the same functions are safe no-ops. Windows deployments use
  the supervisor's job-object integration point; this portable build logs
  `"enforced":"false"` instead of pretending a limit was applied.
