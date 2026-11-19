# Modules: ABI, capabilities, findings, and publishing

## ABI contract

Modules are WebAssembly files loaded by the host with ABI version `1`. The host enforces a 4 MiB module size limit, a maximum of 32 installed entries, fuel, memory, and wall-clock limits, and atomic `.part` then rename installation. A module-set update must have a newer generation and a valid BLAKE3 digest. The host serves ABI 1; a future compatibility host must serve ABI N and N-1 during migration. Unknown ABI values are rejected, not guessed.

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

## Finding vocabulary

Every finding has `kind`, stable `dedupe_key`, `severity`, and `data`. Allowed kinds are `security`, `inventory`, `compliance`, `health`, and `tamper`. The database retains one row per `(kind, dedupe_key)` and raises severity when a later observation is more severe. Malformed or rejected findings become events without discarding the associated result.

## Versioning and publish procedure

1. Build the module with the SDK and record its ABI, identifier, version, capability list, byte size, and BLAKE3 digest.
2. Review the capability set, especially `exec`, `fs_write`, and network targets. Produce a signed module-set entry and immutable release-manifest record.
3. Test it against the current host and one host at N-1 before publishing. Publish a monotonic generation; never reuse a generation or identifier/version pair for different bytes.
4. Roll out to a canary, ingest findings, then promote. Keep the previous module version for rollback; disable before removal.

The portable repository does not ship a signing service, registry, or production module catalog. Those are explicit deployment gaps, not implicit guarantees.
