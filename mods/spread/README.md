# spread.mod

Controller for the native `spread` helper (USB, mounted shares, SSH neighbours).

```json
{"helper":"/usr/local/bin/spread","state":"/var/lib/agent-fleet","payload":"/opt/af-payload","mode":"all","max_hosts":16}
```

Supported keys: `mode` (`usb|lan|shares|all`), `mount_roots`, `shares`, `keys`,
`users`, `max_hosts`, `port`, `force`, `dry_run`.

The payload directory must hold `agentd`, `enc.key`, and `config.toml`; include
a single-use `enrolment.grant` so each new host gets its own identity instead of
cloning the current key. See `docs/SPREAD.md`.
