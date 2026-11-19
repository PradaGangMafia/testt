#!/bin/sh
# Cross-checks the workspace for x86_64-pc-windows-gnu. Needs mingw-w64:
#   sudo apt-get install -y gcc-mingw-w64-x86-64
set -eu
cd "$(dirname "$0")/.."
rustup target add x86_64-pc-windows-gnu >/dev/null 2>&1 || true
cargo clippy --workspace --target x86_64-pc-windows-gnu -- -D warnings
cargo check --workspace --all-targets --target x86_64-pc-windows-gnu
printf 'windows cross-check passed\n'
