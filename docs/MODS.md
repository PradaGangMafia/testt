# Modules: ABI, capabilities, findings, and publishing

## ABI 1

ABI 1 is frozen. A module is a WebAssembly 1.0 binary loaded by the host. A
change to anything in this section is a new ABI; the host serves the current
ABI and the previous one during migration (currently 2 and 1). An entry whose
`abi` is outside `1..=2` is rejected. The host never guesses an ABI, and ABI 1
modules are unchanged by the ABI 2 additions below.

The host enforces a 4 MiB module size limit, at most 32 installed
entries, a 50,000,000 fuel budget, 32 MiB of linear memory, and a 30 second
wall-clock deadline per invocation. Installation is atomic: bytes are written
to `module.wasm.part`, fsynced, renamed to `module.wasm`, the version and id
directories are fsynced, and the installed bytes are re-read and re-verified
before the entry is committed.

### Required exports

| Export | Signature | Meaning |
|---|---|---|
| `memory` | memory | Linear memory. Must be exported. |
| `alloc` | `(i32) -> i32` | Allocate `len` bytes, return a pointer. `0` means allocation failed. |
| `dealloc` | `(i32, i32) -> ()` | Free a pointer/length pair previously returned by `alloc`. |
| `handle` | `(i32, i32) -> i32` | Run with the argument JSON at `(ptr, len)`. Return the guest exit code. |

`alloc` and `dealloc` are required even when the module takes no arguments and
emits no output. A module that does not export `handle` or `alloc` fails to
instantiate; the host reports `missing export: alloc` or
`missing export: handle`. A missing `dealloc` is tolerated and logged. A
`dealloc` failure or trap is logged and never changes the result.

### Required imports

All imports come from the `env` module. Modules may not import anything not
listed here.

| Import | Signature | Capability | Success | Denied | Host error |
|---|---|---|---|---|---|
| `log` | `(ptr, len) -> ()` | none | line recorded | — | — |
| `read_file` | `(ptr, len) -> i64` | `fs_read` | packed bytes | `-1` | `-2` |
| `write_file` | `(ptr, len, ptr, len) -> i32` | `fs_write` | `0` | `-1` | `-2` |
| `exec` | `(ptr, len, ptr, len) -> i64` | `exec` | packed bytes | `-1` | `-2` |
| `http_get` | `(ptr, len) -> i64` | `net` | packed bytes | `-1` | `-2` |
| `clock_ms` | `() -> i64` | `clock` | milliseconds since the Unix epoch | `-1` | `-2` |
| `random` | `(ptr, len) -> i32` | `random` | `0`, buffer filled | `-1` | `-2` |
| `env_get` | `(ptr, len) -> i64` | `env` | packed value; `0` means unset | `-1` | `-2` |
| `sleep_ms` | `(i64) -> i32` | `sleep` | `0`, slept at most 5000 ms | `-1` | `-2` |
| `result` | `(ptr, len) -> ()` | none | payload recorded | — | — |

Arguments named `ptr` are `i32` offsets into the module's linear memory;
`len` is an `i32` byte count. `exec` takes the command as the first pair and a
JSON array of string arguments as the second pair. The host caps `read_file`,
`exec`, `http_get`, and `env_get` output at 1 MiB, an HTTP GET at 1 MiB and
30 seconds, and `sleep_ms` at 5000 ms. A host error is written to the host log
before the error code is returned.

Every pointer/length pair is validated against the current linear memory
before it is read or written. An out-of-range read traps with `oob read`; an
out-of-range write traps with `oob write`. A trap is not a denial: the module
does not get to inspect a code.

### Packed pointer/length results

Imports that return bytes return one `i64`:

```
value = (ptr as i64) << 32 | (len as i64 & 0xffff_ffff)
```

`0` means an empty byte string. Negative values are status codes: `-1` for a
capability denial and `-2` for a host failure. A positive value always names a
range the host allocated through the guest's `alloc` export and filled before
returning. The guest owns that range; ABI 1 does not require the guest to free
it before returning from `handle`, and the host discards the whole instance
after the call.

### Arguments

The host serialises the task's CBOR `args` value to JSON exactly once at the
handler boundary and passes those bytes to `handle`. Arguments that are not
JSON-representable fail before instantiation with `code: -1` and
`stderr: "args not JSON-representable"`.

For non-empty arguments the host calls `alloc(len)`, writes the JSON bytes at
the returned pointer, and calls `handle(ptr, len)`. A zero-length argument
document passes `(0, 0)` without calling `alloc`. If `alloc` returns `0`, the
host returns `code: -1` and `stderr: "guest allocation failed"` without calling
`handle`. The argument bytes are byte-identical to the JSON serialisation; the
guest must not assume a trailing NUL.

The JSON document is an object for all task bodies defined today. A module
must tolerate unknown keys and must not reject a document solely because a key
it does not use is present.

### Results

The guest reports a result by calling `result(ptr, len)` with a UTF-8 JSON
document:

```json
{"ok":true,"stdout":"...","stderr":"","code":0}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `ok` | boolean | no, default `false` | Guest's success flag. |
| `stdout` | string | no, default `""` | Captured output. Truncated at 64 KiB. |
| `stderr` | string | no, default `""` | Failure detail. |
| `code` | integer | no, default `-1` | Guest exit code. |

`ok` is forced to `false` when `code` is nonzero or when `stdout` was
truncated. Nonzero `code` starts at `1` for ordinary guest failures; `-1` is
reserved for host errors. If the guest emits no result, the host synthesises
`{"ok":code == 0,"stdout":"","stderr":""}` from the return value of `handle`.

The last `result` call wins. A second call replaces the first and appends one
`module result replaced` line to the host log. Malformed JSON does not panic:
it becomes `ok: false`, `code: -1`, `stderr: "malformed module result: <raw>"`,
with the raw bytes truncated to 1 KiB. Output beyond 64 KiB is truncated on a
UTF-8 boundary, suffixed with `...`, and forced to `ok: false`.

### Exit and trap codes

| Code | Meaning |
|---|---|
| `0` | Guest returned zero and `ok` was not forced false. |
| guest positive | Guest failure. A result frame is still emitted. |
| `-1` | Host error, malformed result, missing export, or an ordinary trap. Trap detail is `trap: <message>`. |
| `-2` | Fuel exhausted. |
| `-3` | Wall-clock deadline. |
| `-4` | Memory limit exceeded. |

A panic in a module compiled with `panic = "abort"` becomes a trap; it does not
abort the host process. Every invocation runs in a fresh store and instance,
so no guest state survives between calls. A `-4` or `-3` does not poison the
next invocation.

### Worked example

`tests/fixtures/hello.wat` is the reference conformance module:

```wat
(module
  (import "env" "result" (func $result (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"ok\":true,\"stdout\":\"hi\",\"stderr\":\"\",\"code\":0}")
  (func (export "alloc") (param i32) (result i32) (i32.const 512))
  (func (export "dealloc") (param i32) (param i32))
  (func (export "handle") (param i32) (param i32) (result i32)
    (call $result (i32.const 0) (i32.const 46))
    (i32.const 0))
)
```

Running it through the host yields:

```
ok: true
stdout: "hi"
stderr: ""
code: 0
```

The payload at offset `0` is exactly 46 bytes. `hello.wasm` is under 1 KiB.

### Invariants

- The host re-instantiates per invocation and holds no guest state between
  runs.
- The host validates every pointer and length against current linear memory
  and never panics on guest input.
- A denial does not partially write, read, execute, or connect.
- Capability checks happen at call time, not only at install time.
- The host never imports a module-supplied function and never calls an export
  other than `alloc`, `dealloc`, and `handle`.
- Unknown ABI values are rejected, never guessed.
- Every fixture in `tests/fixtures/` is exercised by R12–R17 and the module
  acceptance tests; none are orphaned.

## ABI 2 additions

ABI 2 adds five imports and one capability. Every addition is additive: an ABI 1
module that never imports them behaves exactly as before.

| Import | Signature | Capability | Success | Denied | Host error |
|---|---|---|---|---|---|
| `read_dir` | `(ptr, len) -> i64` | `fs_read` | packed JSON array | `-1` | `-2` |
| `stat` | `(ptr, len) -> i64` | `fs_read` | packed JSON object | `-1` | `-2` |
| `read_file_range` | `(ptr, len, i64 offset, i64 want) -> i64` | `fs_read` | packed bytes | `-1` | `-2` |
| `http_post` | `(url ptr, url len, body ptr, body len) -> i64` | `net` | packed response body | `-1` | `-2` |
| `spool_put` | `(path ptr, path len, kind ptr, kind len, data ptr, data len) -> i64` | `spool` | artifact id | `-1` | `-2` |

- `read_dir` returns `[{"name","kind","size"}]`, sorted by name, at most 2048
  entries. `kind` is `file`, `dir`, `link`, or `other`; symlinks are reported,
  never followed. Policy matches the directory path.
- `stat` returns `{"kind","size","mode"}` without following a symlink.
- `read_file_range` seeks to `offset` and reads at most `want` bytes, capped at
  1 MiB per call, so large files are chunked by the caller.
- `http_post` sends a body capped at 1 MiB and returns the response body, capped
  at 1 MiB. Policy matches the URL.
- `spool_put` appends an artifact to `<state>/spool.db` (SQLite table
  `artifacts`: `id, path, sha256, size, kind, captured_at, data`) and returns
  its row id. The spool is capped at 512 MiB by deleting the oldest 10% when the
  cap is crossed. Policy matches the source path, not the spool location.

`read_file`, `exec`, and `http_get` remain capped at 1 MiB. A module that uses
the ABI 2 imports MUST declare `abi = 2` and the matching capabilities; an ABI 1
entry that imports them is refused at install with `import requires ABI 2`. On
the SDK the matching features are `fs-dir` (`read_dir`, `stat`), `fs-range`,
`net-post`, and `spool`; enabling any of them makes the binary an ABI 2 module.

## Capability table

| Capability | Example | Safe default / gap |
|---|---|---|
| `fs_read` | read an inventory file matching an explicit path glob | Denied by default; native ACL semantics are deployment-owned |
| `fs_write` | write a bounded report to a dedicated directory | Denied by default; never combine casually with `exec` |
| `exec` | run a fixed inventory helper with bounded output | Denied by default; exec + fs_write is root-equivalent for the daemon user |
| `net` | fetch an approved endpoint through the host | Denied by default; DNS/proxy policy is deployment-owned |
| `clock` | read host time for a finding timestamp | Denied by default; clock rollback is not prevented |
| `random` | request host randomness | Denied by default; no portable hardware-entropy attestation |
| `env` | read an allowlisted deployment variable | Denied by default; environment may contain secrets |
| `sleep` | bounded backoff between module requests | Denied by default; scheduler fairness is host policy |
| `spool` | append a collected file to the state SQLite spool | Denied by default; the spool is plaintext and shares the state disk, capped at 512 MiB |

## Finding vocabulary

Every finding has `kind`, stable `dedupe_key`, `severity`, and `data`. Allowed kinds are `security`, `inventory`, `compliance`, `health`, and `tamper`. The database retains one row per `(kind, dedupe_key)` and raises severity when a later observation is more severe. Malformed or rejected findings become events without discarding the associated result.

## Versioning and publish procedure

1. Build the module with the SDK and record its ABI, identifier, version, capability list, byte size, and BLAKE3 digest.
2. Review the capability set, especially `exec`, `fs_write`, and network targets. Produce a signed module-set entry and immutable release-manifest record.
3. Test it against the current host and one host at N-1 before publishing. Publish a monotonic generation; never reuse a generation or identifier/version pair for different bytes.
4. Roll out to a canary, ingest findings, then promote. Keep the previous module version for rollback; disable before removal.

The portable repository does not ship a signing service, registry, or production module catalog. Those are explicit deployment gaps, not implicit guarantees.
