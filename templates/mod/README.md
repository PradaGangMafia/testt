# Agent-Fleet module template

A minimal ABI 1 module that declares no capabilities.

```sh
./build.sh
```

The script builds `src/` for `wasm32-unknown-unknown` in release mode and
prints the `.wasm` path. It fails if the artifact is missing, so a host-target
build can never be mistaken for a module.

## Files

| File | Purpose |
|---|---|
| `src/lib.rs` | Module entry point annotated with `#[mod_main]` |
| `manifest.toml` | Identity, ABI, and declared capabilities |
| `build.sh` | Reproducible wasm build |
| `Cargo.toml` | Release profile sized for module distribution |

## Publishing

1. Edit `manifest.toml`: `id`, `version`, and the exact capability list.
2. Run `./build.sh`.
3. Record the module size and BLAKE3 digest in the signed module-set entry.
4. Install through `adminctl mod add`, then exercise it with `adminctl mod call`.

Capabilities are enforced twice: the store rejects undeclared capabilities and
the host re-checks every call against the daemon policy. Declaring a capability
does not grant it; the daemon's `config.toml` must allow it too.
