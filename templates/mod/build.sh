#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

cargo build --release --target wasm32-unknown-unknown
output="target/wasm32-unknown-unknown/release/mod_template.wasm"

if [[ ! -f "$output" ]]; then
    echo "build failed: $output is not a .wasm file" >&2
    exit 1
fi

echo "$output"
