#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:${PATH}"
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
cargo build --workspace --release
cp target/release/agentd "$ROOT/agentd"
cp target/release/adminctl "$ROOT/adminctl"
cp target/release/relayd "$ROOT/relayd"
chmod 0755 "$ROOT"/*
STATE="$ROOT/state"
mkdir -m 700 "$STATE"
"$ROOT/agentd" install --state "$STATE"
"$ROOT/agentd" install --state "$STATE"
test -f "$STATE/services/agentd.unit"
"$ROOT/adminctl" --state "$STATE" keygen >/dev/null
set +e
"$ROOT/agentd" doctor --state "$STATE" --json >"$ROOT/doctor.json"
RC=$?
set -e
# A sandbox has no configured relay and therefore reports a warning (exit 1),
# but the report must still be valid JSON and contain every required check.
python3 - "$ROOT/doctor.json" "$RC" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
names = {item['name'] for item in report['checks']}
required = {'binary_path','binary_writable','key_permissions','state_writable','lock_acquirable','config_valid','relay_health','peer_table','mod_abi','listen_bindability','database_writable','disk_headroom'}
missing = required - names
if missing:
    raise SystemExit(f'missing doctor checks: {sorted(missing)}')
if int(sys.argv[2]) not in (0, 1):
    raise SystemExit(f'unexpected doctor exit: {sys.argv[2]}')
PY
printf 'launch checks passed; doctor report: %s\n' "$ROOT/doctor.json"
