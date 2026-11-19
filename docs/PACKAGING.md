# Packaging and signing

Releases are built on Debian, signed with Ed25519, and verified before use.

## Build

```sh
scripts/package-release.sh 0.2.0
```

Produces `release-artifacts/0.2.0/`:

- `linux-amd64/` and `windows-amd64/` binaries (Windows needs `gcc-mingw-w64-x86-64`)
- tarballs for the coordinator set and the agent set
- `agent-fleet-coord_0.2.0_amd64.deb` with systemd units and a `postinst` that
  creates the `agentfleet` service account and state directories
- `SHA256SUMS`, `SHA256SUMS.sig`, `agent-fleet-signing.pub`, `RELEASE.json`

The signing key is created at `~/.agent-fleet-signing/key.pem` (0600) on first
run. Back it up; a lost key means a new trust root. `AGENT_FLEET_SIGNING_KEY`
points at another directory.

## Verify

```sh
release-artifacts/0.2.0/verify-release.sh release-artifacts/0.2.0
```

The release directory includes `verify-release.sh` and the public key, so a
recipient can verify without the private key. Verification checks the signature
over `SHA256SUMS` and every checksum.

## Coordinator

```sh
sudo dpkg -i agent-fleet-coord_0.2.0_amd64.deb
sudo -u agentfleet /opt/agent-fleet/bin/adminctl --state /var/lib/agent-fleet keygen
sudo systemctl enable --now agent-fleet-relay agent-fleet-coord
sudo -u agentfleet /opt/agent-fleet/bin/fleetui --state /var/lib/agent-fleet
```

`fleetui` is the terminal dashboard (see `docs/UI.md`).

## Agent host

```sh
payload=/tmp/af-payload && mkdir -p "$payload"
cp agentd enc.key config.toml coordinator.pub "$payload"/
cp enrolment.grant "$payload"/          # or agent.key for a clone
sudo scripts/install-agent.sh --payload "$payload"
```

The installer creates `/opt/agent-fleet/agentd`, a `0600` state directory, an
`agentfleet` system account and an `agent-fleet.service` with mixed kill mode and
a 45 s stop timeout. `--uninstall` keeps state.

## macOS

No macOS binaries are produced on Debian without an SDK. Build on a Mac with
`cargo build --release`; `agentd install` emits a launchd definition. Add those
artifacts and their checksums to `SHA256SUMS` and re-sign before publishing.

## Key custody

- `agent.key` (coordinator signing), `enc.key` (fleet encryption), `coord.key`
  (database) and `artifact.key` never ship in a release.
- `agent-fleet-signing.pem` signs releases only; it is not a wire key.
- Distribute `enc.key` and `coordinator.pub` inside agent payloads over a
  trusted channel.
