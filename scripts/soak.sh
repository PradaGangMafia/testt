#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:${PATH}"
iterations="${1:-120}"
state="${2:-$(mktemp -d)}"
mkdir -p "$state"
trap 'rm -rf "$state"' EXIT
cargo build -p agentd --quiet
for ((i=1; i<=iterations; i++)); do
  ./target/debug/agentd --worker --once --state "$state" >/dev/null
  if [[ -r /proc/$(pgrep -n agentd 2>/dev/null || echo 0)/status ]]; then
    rss=$(awk '/VmRSS:/ {print $2}' "/proc/$(pgrep -n agentd)/status" || true)
    printf 'iteration=%d rss_kib=%s\n' "$i" "${rss:-0}"
  else
    printf 'iteration=%d\n' "$i"
  fi
done
