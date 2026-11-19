# PRE-PLUGIN-BUILD-GUIDE.md

Status: CLOSED — exit gate passed 2026-11-18; see `docs/PLUGIN-READINESS.md`
Owner: operator
Supersedes: nothing (supplements full-build.txt; does not amend it)
Applies to: phases 0–5 remediation, then P33–P40

---

## 1. Purpose

The repository at HEAD is further along in the messaging layer than the README implies and further behind in the plugin layer. `msgfmt` and `transport` are real code with real tests. The daemon wiring, the plugin host boundary, and the SDK are stubs dressed as implementations.

If a botnet mod is written against the current tree it will be written against an ABI that is about to change five ways, and there is no way to observe it failing, because the daemon never polls.

This guide sequences the repair. Work it top to bottom. Do not reorder. Do not skip ahead to mods.

## 2. How to use this guide

- One prompt per session. Never two.
- Paste the full-build.txt preamble and standing rules ahead of the prompt text every time.
- Every prompt ends with `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, and `cargo test --workspace` green.
- Every ACCEPTANCE bullet is a test you write in the same commit that adds the behaviour.
- If a prompt conflicts with the tree, say so and stop. Do not guess and do not silently reinterpret.
- Do not start a prompt until every prompt it lists under DEPENDS is green.

## 3. Standing rules

Carried from full-build.txt. Restated here so a fresh session cannot drift.

1. Rust only. No C, no build scripts that shell out to another toolchain beyond `cargo`.
2. `#![forbid(unsafe_code)]` on every crate. If a prompt appears to need `unsafe`, stop and say why.
3. `#![deny(missing_docs)]` stays. Every public item documented.
4. No `todo!()`, no `unimplemented!()`, no `unreachable!()` outside provably exhaustive matches, no placeholder `Ok(())`.
5. Deterministic: no wall-clock in outputs, no unordered iteration in persisted bytes, no hash-map ordering in serialised form.
6. One new dependency per prompt at most, with a one-line justification in the commit body. `serde_json` is pre-approved for R15. Nothing else is pre-approved.
7. Tests are not optional and not deferred. A prompt with no test is incomplete.
8. Docs updated in the same commit as the behaviour.
9. Bounded everything: buffers, queues, retries, output. A limit without a test is a comment.
10. No behaviour change without a failing test first.
11. `docs/SPEC-AMENDMENTS.md` gets an entry for any deviation from full-build.txt.
12. Commit messages: `R0x: <what>` plus the reason. One concern per commit.

## 4. Per-prompt output contract

Every session returns, in this order:

1. Files added and changed, with a one-line purpose each.
2. The acceptance tests added, quoted.
3. Command output for fmt, clippy, test.
4. Anything the next prompt must know.
5. An explicit statement of what was *not* done.

A session that returns code without the test output is not done.

## 5. Defect index

Every row is confirmed against HEAD, not suspected. Each defect names the prompt that repairs it.

| # | Defect | Location | Repaired by | Blocks |
|---|---|---|---|---|
| D1 | Worker loop never polls. `run_worker` sleeps 300 s, touches `alive`, logs `idle`. `Agent::run()` is uncalled. `--once` returns without polling. | `agentd/src/main.rs` | R01 | everything |
| D2 | Results are plaintext `result=key ok=…` appended to `results.log` and `put()` raw. `Result`/`encode_result` never used by the agent. | `Agent::dispatch`, `fan_out_result` | R02 | P10, P25, P42 |
| D3 | Dispatch is a `match body`. `HandlerRegistry` is dead code. | `Agent::dispatch` | R04, R05 | P33 |
| D4 | `HandlerRegistry` has a semaphore but no queue. Spec: queue 32, drop-oldest. | `plugins.rs` | R04 | P33, P50 |
| D5 | `ModStore::open` never scans its directory. Map and generation are memory-only. Restart loses every mod; replayed `ModSet` re-applies. | `plugins.rs` | R07 | P34, P49 |
| D6 | Mod install has no fsync sequence and no re-verify after rename. | `ModStore::apply` | R08 | P34, P48 |
| D7 | Policy hardcoded `allow_exec: false, allow_net: false, allow_caps: {}`; `default()` at dispatch. Config never consulted. | `poll_all`, `dispatch` | R09 | P35, P51 |
| D8 | `handle` is `() -> i32`. No args import. `HostState.args` written, never read. Mods cannot see args. | `plugins.rs`, `modsdk-macros` | R12, R19 | P36 |
| D9 | `env.result` discards `ptr`/`len`, stores an empty vec, `stdout` hardcoded empty. All module output lost. | `plugins.rs::run_wasm` | R14 | P36 |
| D10 | No `alloc`/`dealloc`/`memory` contract. No pointer or length validation. | `plugins.rs` | R12, R13 | P36 |
| D11 | `check_call` never called. `HostState.policy` dead. Caps enforced only at load. | `plugins.rs` | R13 | P35 |
| D12 | `limits.memory_bytes` unused. No `StoreLimits`. | `plugins.rs` | R16 | P37 |
| D13 | Deadline compared only after return. No epoch interruption. `-3` unreachable, `-4` unreachable, `-2` unmapped. | `plugins.rs` | R17 | P37 |
| D14 | Args are CBOR. Spec says JSON. No `serde_json` in workspace. | workspace | R15 | P36, P43 |
| D15 | Every `Ctx` method returns `Err(CapError::Denied)` unconditionally. Zero extern imports. | `modsdk/src/lib.rs` | R18 | P39 |
| D16 | `#[mod_main]` emits `handle() { let _ = stringify!(name); 0 }`. Annotated fn never called, can never fail. | `modsdk-macros/src/lib.rs` | R19 | P39 |
| D17 | No `examples/`, no template. | repo | R20 | P39 |
| D18 | `tests/integration/` absent. No t01–t10, m01–m11, n01–n12, p01–p13. | `tests/` | R03, R23 | P14, P23, P32, P40 |
| D19 | Crate-root `#![expect(dead_code, …)]` masks unused-field regressions. | `main.rs` | R05 | all |
| D20 | `workspace.repository` is `https://example.invalid/agent-fleet`. | `Cargo.toml` | R21 | P53 |
| D21 | `ModStore` and `WasmHost` are constructed with throwaway policy, so a module's declared caps and its runtime caps can disagree. | `dispatch`, `poll_all` | R09 | P35 |

## 6. Dependency graph

```
A (R01–R03) ──> B (R04–R06) ──> C (R07–R09) ──> D (R10–R11)
                                                    │
                                                    v
                                    E (R12–R15) ──> F (R16–R17)
                                                    │
                                                    v
                                    G (R18–R21) ──> H (R22–R23) ──> EXIT GATE
```

Phase A makes the daemon observable. Phase B gives dispatch a seam. Phase C makes modules durable and policy-driven. Phase D freezes the contract. E through G implement against the frozen contract. H proves it.

---

# PHASE A — MAKE THE DAEMON REAL

Nothing downstream is testable while the loop is a stub and results are text.

## R01 — Worker loop polls

DEPENDS: none
REPAIRS: D1

### Scope

`run_worker` constructs an `Agent` from configuration — channels, verifying key, encryption key, state directory — and drives `Agent::run()`. `--once` calls `poll_once()` exactly once, prints the cycle report, exits 0 on success and 1 on error.

Keep the existing worker preamble, in this order, before the first poll: `apply_resource_policy`, key recovery, mirror restore of `cursors.json`, re-enrol attempt, key mirror, `touch_alive`, replica repair, tamper findings.

`run_worker` remains the only function that touches `alive`. Move the touch into the loop body so it happens every cycle, not once.

The loop must survive any `poll_once` error: log at warn, touch alive, sleep the jittered interval, continue. Never propagate out of the loop.

`Agent::run` gains a shutdown signal so `--once` and tests can stop it deterministically.

### Constraints

- No new dependencies.
- Channel construction comes from config, not from `MockFsChannel` literals.
- A missing or invalid key is exit 2 before any network call.
- `--once` must not sleep.

### Acceptance

- `--once` against a `MockFsChannel` with one queued ping writes exactly one result frame.
- Two consecutive `--once` runs process one frame total; the second reports `processed: 0`.
- An injected `poll_once` error leaves the process alive and the next cycle still runs (test with a channel that errors once).
- `alive` mtime advances every cycle over a three-cycle test.
- `--once` on a fresh state dir exits 0 with `processed: 0`.

---

## R02 — Results are signed frames

DEPENDS: R01
REPAIRS: D2

### Scope

Delete the plaintext result path. `dispatch` builds `msgfmt::Result { task_epoch, agent_pub, ok, stdout, stderr, code }` using the request's `route_tag` and `epoch`, signs with the agent key, calls `encode_result`, and passes the bytes to `fan_out_result`.

Dedupe key stays `route_tag:task_epoch`, held in `results_seen` as today. `results.log` becomes a local audit line only and is never a transport.

`agent_pub` is the enrolled verifying key bytes, not the signing key.

Result frames are size-classed by the existing encoder; a result too large for `MAX_PAYLOAD` is truncated in `stdout` with a `...` suffix and `ok` forced false, rather than failing to encode.

### Constraints

- No change to `msgfmt` frame layout.
- `decode_result` on the coordinator must accept what the agent produces, byte for byte.
- Nonzero module codes still produce a result frame; they are not dropped.

### Acceptance

- A ping result decodes with `decode_result` against the enrolled verifying key.
- A flipped signature byte is `BadSignature`.
- A replayed task does not produce a second frame.
- All four size classes round-trip through the real dispatch path.
- A 5000-byte stdout is truncated with `...` and `ok: false`.

---

## R03 — Regression suite for phases 0–5

DEPENDS: R01, R02
REPAIRS: D18 (partial)

### Scope

`tests/integration/` does not exist. Create it and implement, exactly as full-build.txt defines them:

- `t01`–`t10` (P14)
- `m01`–`m11` (P23)
- `n01`–`n12` (P32)

Use a shared harness in `tests/integration/common/` for temp state dirs, key generation, and channel setup. No test writes outside its temp dir.

### Constraints

- Tests are independent and parallel-safe.
- No sleeps longer than 2 s except where the spec mandates a timeout.
- Whole suite under 120 s.

### Acceptance

- All 33 pass.
- `t03`, `t04`, `t05`, `n03` fail when R02 is reverted.
- Suite is green twice in a row from a clean checkout.

---

# PHASE B — DISPATCH SURFACE

## R04 — Handlers module and registry queue

DEPENDS: R03
REPAIRS: D3, D4

### Scope

Create `agentd/src/handlers/`. Move `Ping`, `Shell`, `Fetch` there behind the existing `Handler` trait. Add `register_all(&mut HandlerRegistry)` that registers them by name.

`HandlerRegistry` gains the queue the spec requires: capacity 32, drop-oldest on overflow, with a dropped counter. A full queue returns a failed outcome, `code: -1`, `stderr: "queue full"`, and increments the counter.

`Mod` becomes a fourth registered handler taking `mod_id`, `version`, `args`, holding `Arc<Mutex<ModStore>>`.

Move `HandlerRegistry` out of `plugins.rs` into `handlers/mod.rs`. `plugins.rs` keeps only `ModStore`, `CapabilityPolicy`, `WasmHost`, `Limits`.

### Constraints

- Registration is explicit; no inventory crate.
- The semaphore stays, behind the queue.
- `handler.rs` holds the trait and `HandlerOutcome`; one definition only (see R06).

### Acceptance

- Duplicate name registration is an error.
- Queue overflow drops the oldest and the loop keeps running.
- The dropped counter appears in the cycle report.
- All R03 tests pass with handlers relocated.

---

## R05 — Dispatch stops matching bodies

DEPENDS: R04
REPAIRS: D3, D19

### Scope

`Agent::dispatch` resolves a handler name from the `TaskBody` variant in one small pure function, then calls `registry.handle(name, args)` and does nothing else. Remove the `Mod` match arm.

Narrow the crate-root `#![expect(dead_code, …)]` to the specific items that still need it, or delete it. Every remaining suppression carries a reason string naming the prompt that clears it.

### Constraints

- Adding a body variant must require no change inside `dispatch`.
- Unknown mod id is a failed result with `code: -1` and `stderr: "unknown or disabled module {id}@{version}"`.
- Disabled mod is the same error text, per P38.

### Acceptance

- `dispatch` contains no `TaskBody` destructuring beyond the name mapping.
- `clippy -D warnings` clean with the crate-level `expect` removed.
- A `Mod` task for a missing id yields `code: -1`.

---

## R06 — One outcome type

DEPENDS: R05
REPAIRS: D3

### Scope

`HandlerOutcome` is defined twice. Keep the one in `handlers/handler.rs`, delete the other, and let `WasmHost` return it directly. Remove both conversion blocks from the `Mod` arm.

### Acceptance

- One definition in the tree.
- `WasmHost::run` returns `handlers::HandlerOutcome`.
- No `From` impls between outcome types remain.

---

# PHASE C — MODULE STORAGE AND POLICY

## R07 — Persist the store

DEPENDS: R06
REPAIRS: D5

### Scope

`<state>/mods/generation` holds the current generation: decimal text, newline, then `blake3:<hex>` of the decimal text. Absent means generation 0.

`ModStore::open` reads it, then walks `<id>/<version>/`. Each version dir holds `entry.cbor` (the `ModEntry`) and `module.wasm`. On open, re-verify size and digest against `entry.cbor`; a mismatch drops that version with one log line and does not abort startup.

`apply` rejects `set.gen <= loaded_generation`, so a replayed `ModSet` after restart is a stale no-op. Write the new generation only after every add in the set has committed.

### Constraints

- Corrupt `generation` file: treat as 0, log once, continue.
- A version dir with no `entry.cbor` is dropped, not fatal.
- `get` still returns `None` for disabled.

### Acceptance

- Mods survive restart and remain callable.
- A truncated `module.wasm` is dropped on open; startup succeeds.
- A replayed `ModSet` after restart returns `StaleGeneration`.
- Fresh dir reports generation 0.
- A corrupt generation file yields generation 0 and one log line.

---

## R08 — fsync and rollback

DEPENDS: R07
REPAIRS: D6

### Scope

Install sequence, in order: write `module.wasm.part`; `sync_all` the file; rename to `module.wasm`; fsync the version dir; fsync the id dir; re-read and re-verify; only then commit to the map and write `entry.cbor`.

Any failure removes the staged version dir and leaves the previous version present and enabled. A failed upgrade of an already-installed `(id, version)` pair restores the old bytes and keeps it enabled.

### Constraints

- Directory fsync via `File::open(dir)?.sync_all()`.
- No partial version dir survives a failure.
- Rollback is verified, not assumed.

### Acceptance

- `kill -9` between each step leaves either the old version running or the new one fully verified. Test by injecting failures at each step.
- A bad digest leaves no directory behind.
- A failed upgrade keeps the previous version enabled and callable.

---

## R09 — Policy from config

DEPENDS: R08
REPAIRS: D7, D21

### Scope

`Agent` holds one `CapabilityPolicy` built from `config.toml`:

```toml
[modules]
allow_exec = true
allow_net = false
allow_caps.fs_read  = ["/etc/**", "/var/lib/inventory/**"]
allow_caps.fs_write = ["/var/lib/reports/**"]
allow_caps.clock    = ["*"]
```

Delete both hardcoded policies. `WasmHost` receives a clone of the agent's policy, and `ModStore::apply` receives the same instance so declared and runtime caps cannot diverge (D21).

Validate once at startup: unknown capability name, or `exec`/`net` declared in `allow_caps` while its floor is false, is exit 2 before any network call.

### Constraints

- `CapabilityPolicy` gains `PartialEq` for test assertions.
- Empty `allow_caps` denies everything, which is the safe default.
- A `*` rule is valid; a rule with no target is invalid.

### Acceptance

- `allow_exec = true` installs an `exec` mod; `false` refuses it at install.
- An unknown cap in config exits 2 with the cap named.
- The policy passed to `WasmHost` is the same value the store validated.
- `allow_caps.clock = ["*"]` permits a clock mod; no `clock` key denies it.

---

# PHASE D — FREEZE THE ABI

Do not write host or SDK code before this phase is committed. Host and SDK are circularly dependent; the document and the fixtures break the cycle.

## R10 — ABI 1 in docs/MODS.md

DEPENDS: R09
REPAIRS: D8, D9, D10, D11

### Scope

Replace the vague ABI paragraph with a complete specification:

**Required exports**

| Export | Signature | Meaning |
|---|---|---|
| `memory` | memory | Linear memory, always exported |
| `alloc` | `(i32) -> i32` | Allocate `len`, return pointer; `0` means failure |
| `dealloc` | `(i32, i32) -> ()` | Free a previous allocation |
| `handle` | `(i32, i32) -> i32` | Run with args at `(ptr, len)`; return exit code |

**Required imports** (`env`): `log(ptr,len)`, `read_file(ptr,len)->i64`, `write_file(ptr,len,ptr,len)->i32`, `exec(ptr,len,ptr,len)->i64`, `http_get(ptr,len)->i64`, `clock_ms()->i64`, `random(ptr,len)->i32`, `env_get(ptr,len)->i64`, `sleep_ms(i64)->i32`, `result(ptr,len)->()`.

Document the packed `i64` return for pointer/length pairs, the denial code, and the args JSON shape.

Document `result` payload: `{"ok":bool,"stdout":string,"stderr":string,"code":int}`. Exit code 0 means ok; any nonzero is a failed result; `-1` is reserved for host errors.

Document the invariants: host re-instantiates per invocation, holds no guest state between runs, validates every pointer and length against `memory.data_size()`, and never panics on guest input.

Freeze it: ABI 1 is immutable; a change is ABI 2, and a future host serves N and N−1. Unknown ABI is rejected, never guessed.

### Constraints

- Every import and export typed. No prose-only signatures.
- Include a worked example module and its expected result.
- State explicitly that modules may not import anything not listed.

### Acceptance

- An engineer can hand-write a conforming module from the document alone; demonstrate with the R11 fixture.
- Every import has a signature, an error code, and a capability name.
- The ambiguity list at the end of the section is empty.

---

## R11 — Fixtures before code

DEPENDS: R10
REPAIRS: D18 (partial)

### Scope

Commit `tests/fixtures/` with `.wat` sources and built `.wasm`:

- `hello.wat` — writes the success JSON through `result`, returns 0
- `bad_abi.wasm` — declares ABI 99
- `loop.wat` — infinite loop
- `hog.wat` — allocates past 32 MiB
- `bomb.wat` — burns fuel without allocating
- `traps.wasm` — `unreachable`
- `no_alloc.wat` — exports `handle` but no `alloc`
- `denied.wat` — calls `write_file` outside any glob

`hello.wat` in full, as the reference conformance fixture:

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

The payload is 46 bytes; assert that count in the fixture build check.

### Constraints

- `.wasm` committed, not built at test time, so tests do not depend on `wat2wasm` being installed.
- Each fixture under 2 KiB.
- `hello.wasm` under 1 KiB.

### Acceptance

- Every fixture behaves exactly as its name says against a stub host.
- `hello.wasm` is under 1 KiB and returns the exact JSON.
- Fixtures are used by R12–R17 and R23; none are orphaned.

---

# PHASE E — HOST IMPLEMENTATION

## R12 — Exports and args delivery

DEPENDS: R11
REPAIRS: D8, D10

### Scope

Implement the export contract. `handle` becomes `(i32, i32) -> i32`. Serialise args to JSON, `alloc` in the guest, write args at the returned pointer, call `handle`, `dealloc` in a `finally` position so it runs on trap too.

Zero-length args pass `ptr = 0, len = 0`. `alloc` returning 0 is a distinct error, `stderr: "guest allocation failed"`.

### Constraints

- No guest memory read or write without a bounds check against `data_size()`.
- A missing `alloc` export fails instantiation with `"missing export: alloc"`.
- `dealloc` failure is logged, not fatal.

### Acceptance

- `hello.wasm` runs and returns its JSON.
- `no_alloc.wasm` fails with the missing-export error.
- Args arrive byte-identical, verified by a fixture that echoes `len`.
- `dealloc` is called on a trapping module (assert via a counter fixture).

---

## R13 — Imports with call-time checks

DEPENDS: R12
REPAIRS: D11, D10

### Scope

Link every import from R10. Each calls `policy.check_call(name, target)` before doing work. Denial returns the documented code and writes a host error string the module can read back.

Validate every pointer and length pair before use; out of bounds traps with `"oob read"` or `"oob write"`, never panics.

`exec` runs through the same bounded runner as the shell handler. `http_get` is capped at 1 MiB and 30 s. `read_file` is capped at 1 MiB. `sleep_ms` is capped at 5000.

### Constraints

- No `unwrap` on guest-controlled values.
- Denial does not partially write.
- Every cap in the table is reachable from a test.

### Acceptance

- `fs_write` outside the glob returns the denial code and writes nothing.
- `denied.wat` fails with the denial code, not a trap.
- A bogus pointer traps with `"oob"`.
- A no-cap module runs.
- `sleep_ms(99999)` returns after 5 s, not 99 s.

---

## R14 — Real `result`

DEPENDS: R13
REPAIRS: D9

### Scope

`result(ptr, len)` copies from guest memory, parses JSON, and fills `HandlerOutcome`. Nonzero `code` forces `ok: false`. Malformed JSON is `ok: false`, `code: -1`, `stderr: "malformed module result"`, with the raw bytes truncated to 1 KiB.

A second `result` call replaces the first and logs once.

### Constraints

- No panic on any byte sequence.
- 64 KiB stdout is preserved intact; beyond that is truncated with `...` and `ok: false`.

### Acceptance

- Output reaches the host intact at 64 KiB.
- Nonzero code yields a failed result.
- Malformed JSON does not panic and reports the truncation.
- Two `result` calls keep the last and log once.

---

## R15 — JSON args

DEPENDS: R14
REPAIRS: D14

### Scope

Add `serde_json` to `[workspace.dependencies]` and to `agentd`. `WasmHost::run` takes `&serde_json::Value`. `TaskBody::Mod.args` stays CBOR on the wire and is converted once at the handler boundary.

### Constraints

- One dependency, justified in the commit body.
- Wire format unchanged.
- Conversion failure is `code: -1`, `stderr: "args not JSON-representable"`.

### Acceptance

- Args round-trip as JSON into the guest.
- A CBOR map with non-string keys is refused with the conversion error.
- Existing `msgfmt` vectors still pass.

---

# PHASE F — LIMITS

## R16 — Memory limit

DEPENDS: R15
REPAIRS: D12

### Scope

Install a `StoreLimits` with 32 MiB through `store.limiter`. Exceeding it returns `-4` with `stderr: "memory limit"`.

### Constraints

- The limit applies to growth, not to the initial 1 page.
- `-4` is distinct from a trap.

### Acceptance

- `hog.wasm` returns `-4`.
- A module allocating 31 MiB succeeds.
- The next task on the same agent runs normally after a `-4`.

---

## R17 — Deadline and trap codes

DEPENDS: R16
REPAIRS: D13

### Scope

Enable `epoch_interruption`. A watchdog calls `increment_epoch` at the deadline and stops when the call returns, on success and on error. Map traps: fuel exhaustion `-2`, epoch deadline `-3`, limiter `-4`. Remove the post-return elapsed comparison.

### Constraints

- Watchdog thread joined on every exit path, including panic.
- Deadline is 30 s from `Limits::default`, overridable.
- No thread leak over 50 runs.

### Acceptance

- `loop.wat` returns `-3` in about 30 s.
- `bomb.wat` returns `-2`.
- `hog.wasm` returns `-4`.
- The next task runs normally after each.
- 50 sequential runs leave no extra threads.

---

# PHASE G — SDK AND EXAMPLES

## R18 — Real `Ctx`

DEPENDS: R17
REPAIRS: D15

### Scope

Every `Ctx` method calls its extern import, copies through `alloc`/`dealloc`, and returns `CapError::Denied` on the documented denial code. Add `Ctx::log`. `Ctx::new` parses the args JSON from `handle`.

`Ctx` stays `!Send`-free and dependency-light; `serde_json` is the only addition.

### Constraints

- No `unsafe` in the SDK.
- Denial and host error are distinct variants.
- Every method has a doc comment with its capability name.

### Acceptance

- Each method denies without its cap and succeeds with it.
- `log` reaches the host log.
- Args parse into `Ctx` and are readable.

---

## R19 — `mod_main`

DEPENDS: R18
REPAIRS: D16

### Scope

The macro emits a real `handle(ptr, len)`: read args, build `Ctx`, call the annotated `fn(&Ctx) -> Result<(), CapError>`, map `Ok` to 0 and `Err` to 1, and emit a `result` with the error text. Keep `#[no_mangle] extern "C"`.

Reject at compile time a signature that is not `fn(&Ctx) -> Result<(), CapError>`, with a readable error.

### Constraints

- The annotated function is actually invoked.
- A panicking module traps rather than aborting the host.
- The macro emits the `result` call before returning nonzero.

### Acceptance

- The annotated fn runs (assert via a side-effect fixture).
- `Err` produces a failed result carrying the message.
- A wrong signature fails to compile with the custom message.
- A `panic!` in a module traps.

---

## R20 — Examples and template

DEPENDS: R19
REPAIRS: D17

### Scope

`crates/modsdk/examples/` with `proc.list`, `net.whoami`, `fs.tree`. Each declares only the caps it uses and emits findings-shaped JSON.

`templates/mod/` with `Cargo.toml`, `src/lib.rs`, `manifest.toml`, `build.sh`, `README.md`.

Release profile for mods: `opt-level = "z"`, `lto = true`, `panic = "abort"`, `strip = true`, `codegen-units = 1`.

### Constraints

- Every example under 100 KiB.
- Template builds and runs unmodified.
- No example imports a cap it does not declare.

### Acceptance

- All three build under 100 KiB.
- Each runs against the host and emits valid findings JSON.
- The template builds, runs, and returns `ok: true` untouched.
- A cap-undeclared example fails at install.

---

## R21 — Target pin

DEPENDS: R20
REPAIRS: D20

### Scope

Add `wasm32-unknown-unknown` to `rust-toolchain.toml`. `build.sh` passes `--target wasm32-unknown-unknown` and fails loudly if the output is not a `.wasm`. Fix `workspace.repository` to the real URL.

### Constraints

- No reliance on ambient `cargo build` for mods.
- `build.sh` is `set -euo pipefail`.

### Acceptance

- `build.sh` emits a `.wasm`.
- A host-target build of an example does not silently pass as the deliverable.
- `Cargo.toml` repository is no longer `example.invalid`.

---

# PHASE H — ADMIN AND ACCEPTANCE

## R22 — adminctl mod surface

DEPENDS: R21
REPAIRS: none (completes P38)

### Scope

`mod add`, `remove`, `enable`, `disable`, `set`, `call`, `list`. `add` and `set` share the agent's validation function; a bad id is refused before publish. `mod call` uses the real host.

### Constraints

- One validation function, imported by both sides.
- Refusal happens before any frame is written.
- `list` shows enabled state, ABI, size, digest, caps.

### Acceptance

- `add` then `set` runs within two cycles.
- A bad id is refused pre-publish and no frame is written.
- `disable` stops execution and leaves files.
- `list` output is parseable.

---

## R23 — p01–p13

DEPENDS: R22
REPAIRS: D18

### Scope

Implement P40 exactly as specified, against the real host and the R11 fixtures.

### Acceptance

- All 13 pass.
- `p05` fails if R13 is reverted.
- `p06`, `p07`, `p08` fail if R16/R17 are reverted.
- `p01` fails if R14 is reverted.

---

# EXIT GATE

Do not author a botnet mod until every line is checked in a single review pass.

- [ ] `agentd --worker --once` polls and emits a signed result frame (supervisor `--once` must not hide a worker failure)
- [ ] an ABI 2 module lists a directory, ranges a file, spools it, and POSTs a report (`abi2` suite)
- [ ] t01–t10, m01–m11, n01–n12 green
- [ ] `dispatch` contains no body match
- [ ] queue is 32 with drop-oldest and a visible counter
- [ ] mods survive restart; a truncated module is dropped, not fatal
- [ ] kill -9 at every install step leaves a valid module or the old one
- [ ] `allow_exec`/`allow_net` come from config; unknown cap exits 2
- [ ] declared and runtime policy are the same instance
- [ ] ABI 1 frozen with all fixtures committed
- [ ] `hello.wasm` returns its JSON through the real host
- [ ] call-time denial writes nothing and returns the documented code
- [ ] `-2`, `-3`, `-4` reachable, distinct, non-leaking
- [ ] every `Ctx` method works and denies correctly
- [ ] examples under 100 KiB; template runs unmodified
- [ ] p01–p13 green
- [ ] `clippy --all-targets -D warnings` clean with the `expect(dead_code)` gone
- [ ] `workspace.repository` real
- [ ] `docs/MODS.md` ABI section matches the implemented host byte for byte

# OUT OF SCOPE UNTIL THE GATE CLOSES

- P41+ findings DB, P47+ tracing, P52+ resilience
- Any new `MsgType` or `TaskBody` variant
- Any new dependency beyond `serde_json`
- Any botnet mod, including `host.info`
- Any performance tuning before correctness

# APPENDIX A — Verification recipes

**Restart persistence**

```sh
agentd --once --state /tmp/s        # install a mod via adminctl first
agentd --once --state /tmp/s        # mod must still be callable
```

**Crash safety**

```sh
for step in part rename verify; do
  INJECT=$step agentd --once --state /tmp/s && \
  cargo test --test integration t0_install_<step>
done
```

**Limit codes**

```sh
agentd mod call loop@1  ; echo $?   # expect -3
agentd mod call bomb@1  ; echo $?   # expect -2
agentd mod call hog@1   ; echo $?   # expect -4
```

**Leak check**

```sh
for i in $(seq 50); do agentd mod call loop@1 >/dev/null; done
ls /proc/$(pgrep agentd)/task | wc -l   # expect stable
```

# APPENDIX B — Why this order

R01 before everything: unobservable work cannot be tested.

R02 before B: mod results travel the same path as every other result. Fixing the path after mods exist means rewriting them.

B before C: the store needs a seam to live behind.

C before D: the ABI needs durable storage and a real policy to be meaningful.

D before E: the contract is frozen before either side is written, which is why the fixtures exist.

E and F before G: the SDK wraps a host that must already enforce.

G before H: acceptance needs examples.

H before the gate: the gate is evidence, not intent.

# APPENDIX C — Rollback

Each phase is independently revertable by commit range. If a phase's tests cannot be made green in two sessions, revert the range, record the blocker in `docs/SPEC-AMENDMENTS.md`, and stop. Do not stack a third attempt on a broken base.

# APPENDIX D — Changelog

| Date | Change |
|---|---|
| 2026-11-17 | Initial guide. Defects D1–D21 confirmed against `202136f`. |
````

Two things worth knowing before you commit this:

**R11's `hello.wat` is the linchpin.** It is the only thing that breaks the host/SDK circular dependency, and it also gives every host test a fixture that cannot lie about what the ABI is. If you cut corners anywhere, don't cut there.

**R15 is the only pre-approved dependency.** `serde_json` shows up in three phases and if it isn't landed cleanly in R15, phases E through G each turn into a separate argument about it.
