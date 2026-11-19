# Resilience (P55–P63)

`agentd install` writes an idempotent service definition and an independent five-minute guard backstop under `<state>/services`. Linux definitions contain `Restart=always`, five-second restart delay, unlimited start interval, and mixed kill mode. macOS definitions are launchd-compatible and include `RunAtLoad`, `KeepAlive` on unsuccessful exit, and throttling. Windows emits an SCM-compatible definition with STOP/SHUTDOWN handling and three restart actions. The sandbox cannot safely register privileged OS services, so a deployment step must install the rendered files into systemd, launchd, or SCM; the generated files are the portable contract used by tests.

The worker atomically touches `<state>/alive` at startup and each polling interval. `guard` treats three polling intervals without a fresh marker as dead and repairs a missing unit without spawning a second worker. `--quick` suppresses the backstop artifact. `uninstall` removes only service artifacts; state, the database, and modules remain.

Three replica roots and three state roots are supported. `AGENT_FLEET_REPLICA_ROOTS` and `AGENT_FLEET_MIRROR_ROOTS` are colon-separated overrides for unprivileged deployments and tests. Replica copies use `.part`, hash verification, rename, and a `manifest.json`. A missing/bad running copy is repaired from the first matching replica; if all copies are bad, the worker continues and reports no fatal error. Mirrored cursor writes are best-effort per root and never turn a mirror failure into a successful primary write failure in the current portable implementation; boot restores an empty primary from the first available mirror.

The enrolled `agent.key` is also mirrored to each configured mirror root with mode `0600` where supported and an adjacent `agent.key.blake3` sidecar. At startup, if the primary key is missing, the worker restores the first key whose length and BLAKE3 sidecar verify, then refreshes all mirrors. `agentd recover-key --state STATE` performs the same recovery explicitly. This is an availability mechanism, not a confidentiality boundary: mirror roots contain equivalent private-key material and must be separately access-controlled or encrypted by the deployment.

`adminctl agents grant --tag <16 hex digits> [--expires <unix-seconds>]` emits a 0600 `enrolment.grant`. A wiped agent with no `agent.key` consumes it once, verifies the signature and expiry, generates a new key, and writes `enrol.request`. The request is a transport hand-off; coordinator-side database ingest and native service registration remain deployment-specific and are intentionally not faked by the portable build.

A worker with no key and no usable grant does not exit. It touches `alive`, backs off for `poll_interval_s`, and retries key recovery and enrolment each cycle, so the guard and supervisor see a live process instead of a restart loop. A grant dropped into the state directory is consumed on the next retry without restarting the process. `--worker --once` without a key prints zero counts and exits zero, which keeps cron one-shots quiet.

Tamper checks record stable names (`key_mode`, `state_mode`, `binary_world_writable`, `binary_hash`) in `tamper.log`. Native `chattr`, macOS codesign, Windows ACL, and privileged service registration are reported as deployment responsibilities because the sandbox has no portable safe API for them. Linux tmpfs detection is implemented: `agentd doctor` fails the `state_durability` check when the state directory is on tmpfs, because it will not survive a reboot. A wall clock behind the last liveness marker is reported as a `clock_monotonic` warning and does not reject state or stop the worker. A read-only or unavailable mirror is skipped where possible. No resilience path self-terminates solely because a hash or mirror check failed.

The `r01–r13` acceptance suite lives in `crates/agentd/tests/resilience.rs`: kill/restart, deleted binary, all replicas bad, wiped state, corrupt mirror, re-enrolment, token reuse and expiry, removed service, stopped unit, permission tamper, modified binary, tmpfs state, and clock rollback.

## Recovery order

1. Run `agentd doctor` and inspect `tamper.log` and `<state>/services`.
2. Run `agentd guard --quick` for a lightweight repair, or `agentd guard` for the full backstop definition.
3. If the primary state is missing, restore from a verifying mirror before starting the first poll.
4. If the key is gone, run `agentd recover-key --state STATE` or restart the worker; a verified key mirror is restored automatically. Only if no verified key mirror exists should an operator place a valid grant at `enrolment.grant`; a running unenrolled worker consumes it on its next retry (no restart needed) and produces `enrol.request`.
5. If the executable is damaged, restore a matching replica or redeploy all copies. Never delete the state or database during binary recovery.
