# Fleet dashboard (TUI)

`fleetui` is a terminal dashboard over the coordinator state. It reads the same
encrypted database as `coordctl` and creates it (and the key) if absent.

```sh
fleetui --state /var/lib/agent-fleet
```

| Key | Action |
|---|---|
| `1`..`5` / `Tab` | switch section |
| `j` / `k` | move selection |
| `v` | revoke or unrevoke the selected agent (Agents tab) |
| `r` | reload now |
| `q` / `Esc` | quit |

Sections: Agents, Findings, Artifacts, Schedules, Events. The header shows live
counts; the footer lists keys. Rows refresh every two seconds.

It is intentionally small and local: no writes except revocation, no module
publishing. Use `coordctl` for schedules, publishing, export and rotation.

Rendering is tested against `ratatui`'s `TestBackend`, so layout regressions fail
in CI without a TTY.
