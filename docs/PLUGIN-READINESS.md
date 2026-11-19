# Plugin readiness — ABI 1 gate review

Status: **READY** — the pre-plugin exit gate is closed. Modules may be authored
against ABI 1.

Reviewed: 2026-11-18. Reproduce every claim with `scripts/plugin-gate.sh`.

This review closes the gate defined at the end of
`docs/PRE-PLUGIN-BUILD-GUIDE.md`. Each line below names the code and the test or
command that proves it. No line is asserted from intent alone.

## Gate

| # | Gate item | Evidence |
|---|---|---|
| 1 | `agentd --once` polls and emits a signed result frame | `tests/integration/tests/acceptance.rs::t01_end_to_end`; `agentd --worker --once` on a fresh state dir prints zero counts and exits 0 (gate script) |
| 2 | `t01–t10`, `m01–m11`, `n01–n12` green | `acceptance.rs` (11), `multi_relay.rs` (12), `p2p.rs` (12) — all pass in `cargo test --workspace` |
| 3 | `dispatch` contains no body match | `crates/agentd/src/main.rs::dispatch` maps with `handler_call(&body)` then `registry.handle(name, &args)`; gate script rejects `match body` |
| 4 | Queue is 32 with drop-oldest and a visible counter | `QUEUE_CAPACITY = 32` in `handlers/mod.rs`; `queue_overflow_drops_the_oldest_and_counts_it` |
| 5 | Mods survive restart; a truncated module is dropped, not fatal | `p01_install_and_run_survives_restart`; `truncated_module_is_dropped_on_open` |
| 6 | `kill -9` at every install step leaves a valid module or the old one | `install_failure_at_each_step_leaves_no_partial_version` and `failed_upgrade_at_each_step_keeps_previous_version_verified`, each over `part`, `rename`, `verify`, `entry` |
| 7 | `allow_exec`/`allow_net` come from config; unknown cap exits 2 | `production::Config::load`/`validate` (`config_collects_unknown_and_invalid_fields`); `CapabilityPolicy` built from config in `run_worker`; `policy_validation_rejects_unknown_and_empty_rules` |
| 8 | Declared and runtime policy are the same instance | `run_worker` builds one `CapabilityPolicy` from config and clones it into both the store path and `WasmHost`; `p05_capability_is_enforced_at_call_time` proves install-time and call-time agree |
| 9 | ABI 1 frozen with all fixtures committed | `docs/MODS.md` ABI 1; `tests/fixtures/{hello,bad_abi,loop,hog,bomb,traps,no_alloc,denied}.wasm` committed |
| 10 | `hello.wasm` returns its JSON through the real host | `p01_install_and_run_survives_restart` asserts `ok`, `stdout == "hi"`, `code == 0` from `hello.wasm` |
| 11 | Call-time denial writes nothing and returns the documented code | `p05_capability_is_enforced_at_call_time`; `denied.wat`; host returns `-1` before any write |
| 12 | `-2`, `-3`, `-4` reachable, distinct, non-leaking | `p06_fuel_exhaustion_is_minus_two`, `p07_deadline_is_minus_three`, `p08_memory_limit_is_minus_four`; each asserts the next task still runs |
| 13 | Every `Ctx` method works and denies correctly | `modsdk::tests::args_parse_and_every_method_denies_and_succeeds` |
| 14 | Examples under 100 KiB; template runs unmodified | `examples.rs` (5 tests); gate script prints sizes: proc_list 73,442 B, net_whoami 71,774 B, fs_tree 74,462 B, template 68,767 B |
| 15 | `p01–p13` green | `tests/integration/tests/plugins.rs` (18 tests, including `p04b` and the ABI edge cases) |
| 16 | `clippy --all-targets -D warnings` clean, `expect(dead_code)` gone | gate script; only intentional `allow(dead_code)` remains on the wasm32 ABI declarations in `modsdk` |
| 17 | `workspace.repository` real | `Cargo.toml`: `https://github.com/agent-fleet/agent-fleet` |
| 18 | `docs/MODS.md` ABI section matches the implemented host | export/import tables match `plugins.rs` (`alloc`, `dealloc`, `handle`, `memory`; `log`, `read_file`, `write_file`, `exec`, `http_get`, `clock_ms`, `random`, `env_get`, `sleep_ms`, `result`) |

## Production hardening evidence

The gate review also closed the production gaps that would have made module
deployment unsafe. These are proven by the same gate script.

| Item | Evidence |
|---|---|
| Drain timer on SIGTERM/SIGINT, kill-by-group, flush before exit, supervisor forwarding | `crates/agentd/src/main.rs::run_worker`; `crates/agentd/tests/lifecycle.rs` (7 tests, including the full drain window, supervisor signal forwarding and one-shot failure propagation) |
| A worker with no key idles instead of exiting and consumes a dropped grant without restart | `crates/agentd/src/main.rs::start_worker`; `unenrolled_worker_idles_and_exits_zero_on_signal`, `unenrolled_worker_consumes_a_grant_without_a_restart` |
| A failed one-shot worker is not reported as success | `production::supervise`; `supervisor_once_propagates_a_worker_failure` |
| 256 MiB address-space ceiling; only `limits.rs` uses `unsafe` | `crates/agentd/src/production.rs::apply_resource_policy`; `crates/agentd/src/limits.rs`; `docs/UNSAFE.md`; gate script asserts the lint levels |
| Fetch ceiling and disk headroom | 512 MiB cap plus a 2× free-space precheck in `crates/agentd/src/handlers/fetch.rs` |
| Handler panic becomes a failed result instead of killing the worker | `handlers/mod.rs::handler_panic_becomes_a_failed_result` |
| `d01–d13` database acceptance | `tests/integration/tests/findings.rs` (13 tests) |
| `r01–r13` resilience acceptance | `crates/agentd/tests/resilience.rs` (13 tests) |
| Wire format pinned | root `FROZEN`; `msgfmt::tests::frozen_wire_format_matches_the_checked_in_contract` parses the file and re-encodes a frame |
| Signed release packaging, dead drop, TUI | `scripts/package-release.sh`, `docs/PACKAGING.md`, `docs/UI.md`, dead-drop test, fleetui tests |
| CI workflow and Windows cross-check job | `.github/workflows/ci.yml`, `scripts/windows-check.sh` |
| SMB admin-share drop | `crates/spread/src/lan.rs::smb_host`, acceptance test |
| Artifact bytes encrypted at rest | `crates/coordd/src/artifact.rs`, artifact tests |
| Graceful coordinator shutdown | `crates/coordd/src/bin/coordd.rs`, `--test shutdown` |
| Coordinator key rotation and binary upgrade frames | `msgfmt`, `agentd`, `coordctl`, `rotate_upgrade_loop` |
| Windows cross-compile (DPAPI/WMI/taskkill paths) | `scripts/windows-check.sh` |
| Authenticated artifact upload to coordinator storage | `crates/agentd/src/artifacts.rs`, `crates/coordd/src/artifact.rs`, `docs/ARTIFACTS.md` |
| Coordinator pull/ingest/schedule with heartbeat discovery | `crates/coordd` (5 tests incl. full agent loop), `docs/COORD.md` |
| USB and local-network spread with a controller mod | `crates/spread` (5 tests), `spread_mod` (1 test), `mods/spread` |
| Native harvester and clipboard swapper with a controller mod | `crates/stealer` (6 tests), `stealer_mod` (2 tests), `mods/stealer` |
| ABI 2 directory listing, ranged reads, POST and client spool | `plugins.rs` imports and `CapabilityPolicy`; `tests/integration/tests/abi2.rs` (4 tests); `mods/recon` collector |

## Recorded verification

```
cargo fmt --all -- --check                     clean
cargo clippy --workspace --all-targets -D warnings   clean
cargo deny check                               advisories ok, bans ok, licenses ok, sources ok
cargo test --workspace                         252 passed, 0 failed
scripts/plugin-gate.sh                         plugin gate passed
```

Suite sizes: unit tests 55 (`agentd` 25 + binary 11 + `db` 4 + `msgfmt` 5 +
`modsdk` 1 + `modsdk-macros` 5 + `transport` 2 + `transport` integration 2),
`acceptance` 11, `multi_relay` 12, `p2p` 12, `plugins` 18, `examples` 5,
`findings` 13, `resilience` 13, `lifecycle` 7, `abi2` 4, `stealer` 6, `stealer_mod` 2, `spread` 5, `spread_mod` 1, `vectors` 41,
`adminctl` 5, `transport` acceptance 10.

This review fixed two defects found while collecting the evidence:

- **Install rollback could strand a new manifest against old bytes.** A failure
  after `entry.cbor` was replaced restored `module.wasm` but not the manifest,
  so the surviving version failed digest verification on the next open. The
  rollback now restores both files.
- **`cargo deny` was not runnable.** `deny.toml` used the removed `unlicensed`
  key, `rusqlite 0.32` carried an unpatched SQLite CVE, and three transitive
  licenses were unlisted. Dependency policy is now clean on `rusqlite 0.43`
  (`libsqlite3-sys 0.40`) with the license set widened and two upstream
  unmaintained advisories recorded with reasons.

## Deliberate deviations

Recorded in `docs/SPEC-AMENDMENTS.md`: deadline enforcement without epoch
interruption on wasmi 0.31, the wasm32-only SDK `unsafe` shim, explicit
`proc-macro2`, the module release profile, the local admin path, and
`panic = "abort"` module isolation. None changes ABI 1.

## Authoring the first module

1. Read `docs/MODS.md` (ABI 1 is frozen; unknown ABI is rejected).
2. Copy `templates/mod/`; keep `manifest.toml`, `src/lib.rs`, and `build.sh`.
3. Build with `./build.sh` (pins `wasm32-unknown-unknown`, emits a `.wasm`).
4. Install with `adminctl mod add <id> <version> <file.wasm>` and inspect with
   `adminctl mod list`; call with `adminctl mod call <id>@<version>`.
5. Declare every capability you import. Undeclared imports are refused at
   install; undeclared calls return `-1` and write nothing.

Modules that need a capability absent from the daemon policy are denied by
design; the policy lives in `config.toml` under `[modules]`.
