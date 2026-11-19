# Agent-Fleet launch report

Date: 2026-11-15. Build scope: P64 doctor, P65 documentation, and P66 launch/package preparation.

## Measurements completed in this sandbox

- Workspace source was formatted with `cargo fmt --all` and compiled with `cargo check --workspace` using the installed stable toolchain.
- `scripts/launch-check.sh` performs a release build, copies binaries outside `target/`, installs the portable service definitions twice, creates an admin identity, and validates JSON doctor output and all required check names.
- Doctor checks are independent and bounded: missing or unreachable relays do not prevent filesystem, configuration, module, database, or disk checks from running. `agentd doctor --json` emits stable `name`, `status`, and `detail` fields.
- Package inputs are `agentd`, `adminctl`, `relayd`, `release-artifacts/SHA256SUMS`, the service definitions emitted by `agentd install`, and the operator documents in `docs/`.

## Not measured here

The sandbox has no four-provider relay fleet, onion relay, coordinator deployment, rebooted Linux/macOS/Windows VMs, production signing/notarisation credentials, or real NAT paths. Therefore this report does **not** claim all-five-target builds, signatures, native service registration, 60-second reboot polling, peer promotion, cross-OS behavior, 100k-finding RSS, or a v1.0.0 tag. Native platform actions remain deployment-owned as documented in `docs/THREAT-MODEL.md` and `docs/RUNBOOK.md`.

## Operator completion record

For a real launch, attach: target/toolchain versions, signed artifact hashes, relay provider and `/health` timestamps, each host's enrolment and doctor JSON, database finding counts, reboot/poll measurements, failover cycle counts, mirror restore and total-wipe re-enrolment evidence, and service-manager logs. Do not mark the final gate complete until every unchecked item in `full-build.txt` has corresponding evidence.
