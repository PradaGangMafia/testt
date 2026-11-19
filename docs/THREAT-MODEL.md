# Agent-Fleet threat model

## Scope and trust boundaries

The agent, coordinator database, relay set, peer channels, module runtime, filesystem, and service manager are separate trust boundaries. Frames are authenticated and encrypted, but availability and metadata exposure are not equivalent to confidentiality. Operators must provision keys, protect state directories, and validate the signed release manifest.

## Threats and mitigations

- **Relay or peer withholding:** a relay can omit, delay, reorder, or selectively withhold frames. Cursors, duplicate suppression, relay quorum, peer replication, and bootstrap reset reduce loss, but cannot prove that an unavailable relay delivered nothing.
- **Poll-loop traffic analysis:** fixed polling with bounded jitter reduces exact timing correlation but does not hide endpoint, volume, or coarse activity patterns. Use an approved network privacy layer when this matters.
- **Supernodes as high-value targets:** supernodes aggregate peer reachability and relay knowledge. Minimize their role, rotate keys, restrict management access, and treat compromise as a fleet-wide incident.
- **Symmetric-NAT punch failure:** direct UDP punching is best effort. Tiered relays remain the recovery path; a sandbox cannot certify NAT behavior without real networks.
- **Plaintext findings at rest:** the portable database and logs are plaintext files protected by filesystem permissions. Encrypt storage or use an encrypted volume when findings are sensitive.
- **Coordinator key as a single point of failure:** protect and offline-back up the coordinator signing/encryption keys. Rotation and re-enrolment require an operator-approved grant; compromise requires revocation and fleet re-enrolment.
- **Modules with `exec` plus `fs_write`:** that combination is root-equivalent from the module policy perspective if the daemon user has those rights. Default-deny capabilities, narrow path globs, signed module manifests, fuel, memory, and time limits are mandatory; never grant these capabilities to unreviewed code.

## What resilience does not cover

Portable Rust code does not register privileged services, enforce native ACLs, set `chattr`, perform macOS notarisation, manage Windows SCM, detect every tmpfs or quota configuration, or guarantee kernel-level resource limits. Generated service definitions are contracts for a deployment team, not proof that a service is installed. Relay health checks prove only a bounded HTTP response at check time. The sandbox has no four-provider fleet, rebooted VMs, onion service, or cross-OS evidence; those launch-gate items remain explicitly unproven until measured in deployment.

## Operator response

Treat a `fail` doctor check, altered binary hash, key permission warning, missing mirror, repeated relay failures, or unexpected module capability as an incident. Preserve `tamper.log`, the JSON doctor output, service-manager logs, and the release manifest before repair.
