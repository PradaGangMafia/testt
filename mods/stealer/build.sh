#!/bin/sh
set -eu
cd "$(dirname "$0")"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --release --target wasm32-unknown-unknown
printf '%s\n' "$(pwd)/target/wasm32-unknown-unknown/release/mod_stealer.wasm"
