# Production operation (P47–P54)

## P47 tracing

`agentd` writes JSON Lines to `<state>/agentd.log`. Events contain a UTC timestamp, level, message, and explicitly selected non-secret fields. The logger rotates at 10 MiB and retains five generations; callers must use stable identifiers (channel id, frame index, message type, route tag, epoch, outcome, duration, and module id) rather than frame bytes. A panic hook records a redacted location event. `RUST_LOG` remains available to deployments that wrap the process with an external logger; the built-in logger is intentionally dependency-free.

## P48 state integrity and P49 lifecycle

`production::atomic_write` writes a temporary file, flushes and syncs it, renames it into place, and syncs the containing directory. It appends a BLAKE3 trailer and preserves the previous valid file as `.bak`; `read_verified` restores that backup when the primary is damaged. `InstanceLock` uses an exclusive lock file and releases it on drop. The default process is the supervisor; it owns the lock and starts `agentd --worker`, restarting with 1–300 second exponential backoff. `--once` makes the worker perform one lifecycle cycle and is intended for cron and tests; in supervisor mode it propagates a failed worker status to the caller.

## Artifact upload (P67)

`agentd` optionally drains its SQLite spool to a coordinator endpoint after each cycle. `artifact_url` in `config.toml` enables it; each row is one SHA-256-verified POST signed with the agent's own key and is deleted only on acknowledgement. `artifact_token`, if present, is a shared second factor. See `docs/ARTIFACTS.md`.

## Self-enrolment and per-agent keys (P69)

There are no per-host secrets. A worker with no `agent.key` generates one (0600) and announces its public key plus a freshly generated per-agent `enc.key` in a signed heartbeat encrypted under the public bootstrap key. The coordinator records both on first contact (trust on first use) and from then on encrypts tasks, module sets, relay sets and upgrades to that agent's key only. Results are encrypted with the same per-agent key and verified by the agent's signature. Losing one host's key exposes that host, not the fleet. Grants still work and set an explicit identity.

## Dead drop bootstrap (P68)

An agent with `dead_drop_url` fetches a signed relay set at startup, verifies it with `coordinator.pub`, persists it, and builds channels from the relay registry. The drop carries no commands and needs no token; see `docs/COORD.md`.

## P50 resources and P51 configuration

The handler registry remains bounded to eight concurrent handlers. Fetches stream through a `.new` file and rename only after completion; they refuse a response over 512 MiB and require twice the expected size in free disk before writing. `Config::load` is strict about fields and capability names, collects all parse errors before returning, and probes state paths before any network operation.

The worker enforces a 256 MiB address-space ceiling at startup through `limits::apply_memory_limit` (`setrlimit(RLIMIT_AS)`); `AGENT_FLEET_MEMORY_LIMIT` overrides the value. The same module owns process-group kill and `statvfs`. It is the only module allowed to use `unsafe`: `agentd` lowers its lint to `deny(unsafe_code)` and applies `#[allow(unsafe_code)]` there only, with the safety arguments recorded in `docs/UNSAFE.md`. Non-Unix builds log `"enforced":"false"` and defer to the supervisor's job-object integration point.

## P52 shutdown and P53 release

The worker installs SIGTERM/SIGINT handling before any startup work, including replica repair. On a signal it stops the polling loop between cycles — including before the first cycle if the signal arrived during startup — gives in-flight handlers `AGENT_FLEET_DRAIN_MS` (default 30 seconds) to finish, then kills any surviving child process groups with `SIGKILL` and flushes pending result frames before exiting zero. Shell tasks and Wasm `exec` calls spawn with `process_group(0)`, so children cannot outlive a deploy. The supervisor installs its own handler and forwards SIGTERM to the worker before waiting for it, so a systemd/launchd stop drains instead of orphaning the worker; the supervisor then exits zero. A worker with no key and no grant idles and retries enrolment rather than exiting two, so the supervisor does not spin. `crates/agentd/tests/lifecycle.rs` proves both directions: a worker stays alive at drain + 2 s without a signal, and exits zero after SIGTERM with a shell task in flight. It also proves the configured drain window is not truncated, that the supervisor forwards the signal and exits zero, and that an unenrolled worker idles yet consumes a dropped grant without restart. The `run_does_not_start_a_cycle_when_shutdown_is_already_set` unit test covers a signal that lands before the first poll.

Release profiles in the workspace use LTO, one codegen unit, aborting panics, and stripping where supported. `scripts/release-check.sh` runs formatting, tests, strict Clippy, dependency policy checks when installed, and emits a SHA-256 manifest.

## P54 soak

`scripts/soak.sh` is a bounded local soak harness. It starts a one-shot worker repeatedly, records RSS and exit status, and exits non-zero on a failed iteration. It is a smoke/soak harness, not a substitute for the specified 48-hour five-agent/four-relay production exercise; network fault injection and real upgrade/mod orchestration require the deployment environment.
