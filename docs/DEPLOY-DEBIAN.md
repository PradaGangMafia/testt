# Deploy on Debian

Two scripts. One command each.

## Server

```sh
git clone <repo> agent-fleet
cd agent-fleet
sudo ./scripts/deploy/install.sh --url https://<public-ip>.sslip.io
```

That installs `relayd` on `127.0.0.1:8788`, `coordd` on `127.0.0.1:8790`,
generates the coordinator keys and artifact token, and puts Caddy in front with a
real certificate on the URL you pass. `http://host:port` also works and skips
TLS. Port 80 must be reachable so Caddy can get the certificate.

Verify:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://<public-ip>.sslip.io/health
```

`200`.

## Payload

On the same server:

```sh
sudo ./scripts/deploy/build.sh --url https://<public-ip>.sslip.io --out ./agentd
sha256sum ./agentd
```

The result is one file. `config.toml`, the artifact token and `coordinator.pub`
are embedded; nothing else travels with it.

## Host

Copy `agentd`, run it:

```sh
scp ./agentd target:/tmp/agentd
ssh target 'chmod +x /tmp/agentd && /tmp/agentd'
```

No arguments, no state directory to prepare. First start generates `~/.af` with
its own `agent.key`, writes the embedded config, and enrols by heartbeat.

For persistence, run it as a service from any directory:

```sh
ssh target 'sudo /tmp/agentd install --enable'
```

Check enrolment on the server:

```sh
coordctl --state /srv/coord agents
```

## Notes

- The binary is built for the server's architecture; build on an x86_64 box for
  x86_64 targets, on arm64 for arm64.
- The token is baked in at build time. Rotate it and you re-run `build.sh`.
- `/srv/coord` holds the keys and database. Back up `agent.key`, `enc.key` and
  `artifact.key`; losing `agent.key` stops all task signing.
- `coordctl --state /srv/coord artifact prune --before <epoch>` is the only
  cleanup for stored files.
