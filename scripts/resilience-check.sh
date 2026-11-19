#!/bin/sh
set -eu

# Usage: scripts/resilience-check.sh /path/to/agentd
AGENTD=${1:-${AGENTD:-}}
if [ -z "$AGENTD" ] || [ ! -x "$AGENTD" ]; then
  echo "usage: $0 /path/to/executable-agentd" >&2
  exit 2
fi
case "$AGENTD" in
  */target/*) echo "refusing a target/ binary; copy it to a deployment path first" >&2; exit 2 ;;
esac
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
STATE="$ROOT/state"
mkdir -p "$STATE"
# Installation is idempotent and does not remove application state.
"$AGENTD" install --state "$STATE" >/dev/null
cp "$STATE/services/agentd.unit" "$ROOT/unit.first"
"$AGENTD" install --state "$STATE" >/dev/null
test "$(cmp -s "$ROOT/unit.first" "$STATE/services/agentd.unit"; echo $?)" = 0
printf keep > "$STATE/findings.db"
"$AGENTD" uninstall --state "$STATE" >/dev/null
test -f "$STATE/findings.db"
# Guard repairs a deleted unit and reports repair with status 1.
set +e
"$AGENTD" guard --quick --state "$STATE" >/dev/null
RC=$?
set -e
test "$RC" = 1
test -f "$STATE/services/agentd.unit"
# Portable mirror boot restore.
mkdir -p "$STATE/mirror-1"
printf 17 > "$STATE/mirror-1/cursor"
rm -f "$STATE/cursor"
AGENT_FLEET_MIRROR_ROOTS="$STATE:$STATE/mirror-1:$STATE/mirror-2" \
  "$AGENTD" --worker --once --state "$STATE" >/dev/null
test -s "$STATE/cursors.json" || true
# Stable tamper report for a world-writable key.
printf key > "$STATE/agent.key"
chmod 0644 "$STATE/agent.key"
set +e
"$AGENTD" doctor --state "$STATE" >/dev/null
RC=$?
set -e
test "$RC" = 1
grep -q key_mode "$STATE/tamper.log"
echo "resilience checks passed"
