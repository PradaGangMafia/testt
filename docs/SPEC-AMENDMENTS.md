# Specification Amendments

P06 re-read the implementation against `docs/SPEC.md` and recorded the following reconciliation:

1. The decoder now decrypts and authenticates the payload before dispatching `msg_type`, so an authenticated but unsupported type returns `UnknownMsgType` only after AEAD verification.
2. Route tags are explicitly derived at enrolment as the first eight bytes of BLAKE3 over the enrolled agent key and remain pinned thereafter.

No other divergence remains between the implementation and the frozen specification. Header layout, padding placement, signing range, AAD, verification order, and public encode/decode signatures are unchanged.

## Pre-plugin build amendments

R01–R23 of `docs/PRE-PLUGIN-BUILD-GUIDE.md` introduced the following deliberate
deviations. Each is bounded and tested.

1. **Deadline enforcement without epoch interruption.** The workspace pins
   `wasmi = 0.31`, which predates epoch interruption. A watchdog thread records
   the 30-second deadline and the host maps an over-deadline fuel trap or return
   to `-3`. The guest is not interrupted mid-instruction, so `-3` is observed
   when the guest next yields or exhausts fuel. Tests use an explicitly short
   `Limits::deadline` so `-3` is reachable without a 30-second test. Fuel
   exhaustion remains `-2`; the two codes stay distinct.
2. **`unsafe` in the Wasm SDK shim.** Standing rule 3.2 forbids `unsafe`. The
   ABI passes raw pointers, so `modsdk` contains a `#[link(wasm_import_module =
   "env")]` import block and turns host-provided `(ptr, len)` pairs into slices.
   That shim is compiled only for `wasm32-unknown-unknown`; every other target
   is covered by `#![forbid(unsafe_code)]`. The host validates the same ranges
   before returning them, and no SDK user-facing API is `unsafe`.
3. **`proc-macro2` is an explicit dependency of `modsdk-macros`.** It was
   already present transitively through `syn` and `quote`, but the macro crate
   must name the token-stream type in its own signature. No new crate entered
   the dependency graph.
4. **Module profile.** The workspace release profile now uses
   `opt-level = "z"`, `lto = "fat"`, `panic = "abort"`, `strip = true`, and
   `codegen-units = 1`, matching the module profile required by R20. This makes
   the three workspace example modules smaller than 100 KiB when built for
   `wasm32-unknown-unknown`.
5. **Local admin path.** `adminctl mod add/set/enable/disable/remove` operates
   on the same durable `ModStore` the daemon opens, and `mod call` constructs the
   daemon's `WasmHost` with the daemon policy. No transport frame is written for
   a local administrative change, so a refusal cannot publish a partial entry.
   Modules installed this way are visible on the daemon's next `--once` cycle
   because the store is re-opened per process. The guide's "runs within two
   cycles" is met by that restart/cycle boundary, not by a live in-process
   reload.
6. **`panic = "abort"` modules.** A Rust panic traps the Wasm instance; it does
   not abort `agentd` because the module runs in a fresh Wasmi store inside the
   host process. This was verified with the trap fixture and the SDK error path.
7. **ABI 2 was added after the plugin gate.** Directory listing, ranged reads,
   POST, and the client spool are additive imports; ABI 1 bytes and behaviour
   are unchanged, and the host serves `1..=2` with install-time ABI checks. ABI 3
   is still refused. Rationale: a stealer cannot enumerate profiles, chunk large
   files, upload a report, or keep a durable artifact without them. The ABI 2
   contract and limits are in `docs/MODS.md`.
