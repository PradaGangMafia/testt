# Agent-Fleet operator runbook

This runbook describes the portable contract and labels deployment-owned steps. Run commands as the service account unless a platform administrator is explicitly required.

## Install and enrol

1. Copy a signed release binary outside `target/`, verify `release-artifacts/SHA256SUMS`, create a 0700 state directory, and run `adminctl keygen --state STATE` where a new identity is required.
2. Initialise the coordinator database with `adminctl db init --state COORDINATOR_STATE`. Grant a wiped host with `adminctl agents grant --state COORDINATOR_STATE --tag TAG --expires UNIX_SECONDS`; transfer the single-use `enrolment.grant` securely.
3. Run `agentd install --state STATE --enable`, then have the platform administrator install the rendered files under `STATE/services` into systemd, launchd, or SCM. The sandbox only writes portable definitions.
4. Run `agentd doctor --state STATE --json` and save the output. A relay failure is independent and does not suppress the other checks.

## Rotate, upgrade, rollback, and revoke

Rotate coordinator material using the existing signed key-rotation procedure, retain the previous key only for the documented grace period, then revoke the old identity at the coordinator. For upgrades, verify the signed hash manifest, stage beside the current binary, stop the supervisor, replace atomically, run doctor, and retain the previous binary until one successful polling cycle. Roll back by restoring the previous verified binary without deleting state or the database. Revoke by removing the agent enrollment and issuing no further grants; recover the host only with a newly signed grant.

## Recovery procedures

- **Corrupted state:** stop the supervisor, preserve the directory, run doctor, and restore the first verifying mirror. Do not overwrite a newer verified cursor with an unverified copy. Restart only after `agentd doctor` has no failures.
- **Total relay loss:** preserve local outbox and pending results, wait for the configured bootstrap reset, then allow peer recovery. Do not treat a successful local process as proof of network delivery.
- **Key or total state loss:** stop the worker and run `agentd recover-key --state STATE`; if a verified mirror contains `agent.key`, it is restored without re-enrolment. For total loss with no key mirror, restore the verified state backup; only then use a valid unexpired grant. Without a key or grant the worker still runs and idles, so the guard does not restart-loop; dropping the grant into the state directory is enough and needs no restart. The next cycles create `agent.key` and `enrol.request`; coordinator-side ingest and service registration are deployment steps.
- **Binary deleted or modified:** stop the supervisor, restore a matching replica or signed package, verify the hash, and retain state. Do not delete the database to repair an executable.
- **Service or unit deleted:** run `agentd guard --state STATE`; it returns 1 when it repairs the portable definition. Re-register that definition with the native service manager.
- **Stale liveness or repeated kills:** inspect `alive`, `agentd.log`, and service-manager logs; run `guard --quick` for the lightweight repair and `guard` for the backstop definition. A portable guard does not spawn a second worker.
- **Permission tamper:** preserve `tamper.log`, correct `agent.key` to 0600 and state to 0700 on Unix, then rerun doctor. Native ACL and immutability checks remain platform-owned.
- **Clock rollback:** preserve logs and verify NTP. The portable cursor accepts a non-forward wall clock; timestamp interpretation and fleet time discipline remain operator responsibilities.

## Routine checks

Run `agentd doctor --state STATE --json` before and after releases, rotations, and recovery. Run `scripts/resilience-check.sh /deployment/path/agentd` in a disposable state. Keep the JSON report, release manifest, service definition, relay health evidence, and database backup with the change record.
