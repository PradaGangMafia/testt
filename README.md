# Agent-Fleet

Agent-Fleet is a secure peer-messaging framework for a Swiss-based operator, organized as a signed and encrypted message-format library, transport abstraction, agent daemon, administration CLI, relay service, findings database, and capability-gated module runtime.

## Current operator entry points

- `agentd doctor --state STATE --json` runs independent binary, key, state, lock, config, relay `/health`, peer-table, module ABI, listen, database, disk, and tamper checks.
- `scripts/plugin-gate.sh` reproduces the pre-plugin exit gate: formatting, strict Clippy, dependency policy, the full workspace suite, ABI fixtures, module size limits, and a fresh-state `agentd --once` poll.
- `scripts/release-check.sh` performs formatting, workspace tests, strict Clippy, optional cargo-deny, release build, and a hash manifest.
- `scripts/resilience-check.sh /deployment/path/agentd` exercises portable service, guard, mirror, and tamper behavior in a disposable state.
- `scripts/launch-check.sh` runs the sandbox-safe release/install/doctor acceptance path.

Read [`docs/RUNBOOK.md`](docs/RUNBOOK.md), [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md), [`docs/MODS.md`](docs/MODS.md), and [`docs/LAUNCH-REPORT.md`](docs/LAUNCH-REPORT.md) before deployment. The sandbox writes portable service definitions but does not register privileged systemd, launchd, SCM, notarisation, or provider infrastructure; those steps require the deployment environment and must not be inferred from a passing local check.

## Module runtime

ABI 1 is frozen and the pre-plugin exit gate is closed; [`docs/PLUGIN-READINESS.md`](docs/PLUGIN-READINESS.md) maps every gate item to its test. `templates/mod/` builds an installable module unmodified, and `crates/modsdk/examples/` contains the three reference modules. Install and inspect modules with `adminctl mod add`, `mod list`, and `mod call`.

At startup, an agent automatically restores a missing `agent.key` from the first configured mirror whose 32-byte key and `agent.key.blake3` sidecar verify. To request this recovery explicitly, run `agentd recover-key --state STATE`. Mirror roots contain equivalent private-key material and must be protected as secrets; delete or rotate all key mirrors when intentionally revoking an identity.
