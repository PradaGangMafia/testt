# Handover checklist

Everything below is either proven in this tree or explicitly deployment-owned.
Do not claim a line until the evidence exists.

## Proven in the tree (reproducible)

| Item | Command |
|---|---|
| Wire format pinned, heartbeats, results, rotation, upgrades | `cargo test -p msgfmt` |
| ABI 1 and ABI 2 host contract | `cargo test -p integration-tests --test abi2` |
| Module install/rollback, capabilities, limits | `cargo test -p integration-tests --test plugins` |
| Findings, ingest, FTS, backup | `cargo test -p integration-tests --test findings` |
| Resilience: kill, wipe, mirror, grant, tamper | `cargo test -p agentd --test resilience` |
| Lifecycle: drain, supervisor, unenrolled idle | `cargo test -p agentd --test lifecycle` |
| Harvester, Firefox NSS, clipboard swapper | `cargo test -p stealer` |
| USB, shares, SSH spread | `cargo test -p spread` |
| Coordinator loop, artifact chain, rotation, upgrade | `cargo test -p coordd` |
| Full gate | `scripts/plugin-gate.sh` |
| Deploy/drain checks | `scripts/resilience-check.sh <copied binary>` |

## Deployment-owned (no evidence here)

1. Build and sign all five targets; notarise macOS; sign Windows. The workspace
   **cross-compiles clean** for `x86_64-pc-windows-gnu` with mingw
   (`scripts/windows-check.sh`: clippy `-D warnings` and `--all-targets`), which
   proves the DPAPI/WMI/`taskkill` paths compile. Windows runtime behaviour and
   signing remain unimplemented here.
2. Register the portable service definitions with systemd/launchd/SCM and prove
   they survive reboot. The files are contracts, not installed services.
3. One VM per OS: install, enrol, reboot, confirm polling within 60 s.
4. Four real relays across providers with two tier 0, one onion, one tier 2;
   record `/health`, failover, and the two-down/three-down exit matrix.
5. Real NAT paths and hole punching.
6. `doctor` clean on every host; record the JSON.
7. 100k-finding export under 50 MiB RSS; 48-hour soak; 50-kill loop.
8. External (off-host) key/state mirrors; total-wipe recovery from them.
9. Chromium v20 app-bound and Firefox master-password behaviour on real Windows
   and macOS profiles.
10. Defender exclusions / real-time toggling with an elevated service account.
11. TLS termination and token distribution for relays and the artifact endpoint.
12. Module signing service/registry; the frame is signed, but publishing is
    manual.
13. Publish a real signed release (the packaging script produces and signs one
    locally; the first campaign build still needs an operator run and key custody).
14. Run CI on the real repository (GitHub Actions workflow is committed; the
    first run and branch protection are owner actions).

## Decisions to make before a campaign

- Privilege level: root/SYSTEM is required for Defender, persistence, drivers,
  and USB launchers that touch other users. The portable daemon has no elevation
  path of its own.
- Enrolment policy: open self-enrolment (TOFU) is the default; grants exist for
  explicit identity. Anyone with `coordinator.pub` and the public bootstrap key
  can enrol — revoke unwanted hosts. A shared `enrol_secret` is not implemented.
- State disk encryption: artifact bytes and the coordinator database are
  encrypted at rest; the bot spool is still plaintext.
- Retention: spool 512 MiB per bot (oldest 10% pruned), artifacts pruned by CLI
  only.
- Poll interval and jitter per config; there is no server-pushed sleep policy.

## Known functional gaps

- No fuzzing and no external security audit.
- Dead drop is a signed relay-list fetch only; there is no command dead drop.
- SMB is a credentialed admin-share drop with optional `winrs` execution; no
  WinRM protocol implementation, no password reuse.
- No artifact download-resume or compression.
- No task cancellation, priority, or per-agent concurrency control.
- `coordd` has no HTTP control API and no graceful SIGTERM drain.
