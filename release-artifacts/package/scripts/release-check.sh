#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:${PATH}"
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
if command -v cargo-deny >/dev/null 2>&1; then cargo deny check; else echo 'cargo-deny not installed; dependency policy check skipped' >&2; fi
mkdir -p release-artifacts
cargo build --workspace --release
rm -rf release-artifacts/package
mkdir -p release-artifacts/package/bin release-artifacts/package/docs release-artifacts/package/scripts
cp target/release/agentd target/release/adminctl target/release/relayd release-artifacts/package/bin/
cp docs/THREAT-MODEL.md docs/RUNBOOK.md docs/MODS.md docs/LAUNCH-REPORT.md release-artifacts/package/docs/
cp scripts/release-check.sh scripts/resilience-check.sh scripts/launch-check.sh release-artifacts/package/scripts/
sha256sum release-artifacts/package/bin/* > release-artifacts/package/SHA256SUMS
tar -czf release-artifacts/agent-fleet-portable.tar.gz -C release-artifacts package
(cd release-artifacts && sha256sum package/bin/* agent-fleet-portable.tar.gz > SHA256SUMS)
printf 'release checks passed; manifest: release-artifacts/SHA256SUMS\n'
