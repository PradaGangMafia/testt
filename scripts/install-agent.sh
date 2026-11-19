#!/bin/sh
# Installs an agent on a Debian host from a payload directory.
#
#   install-agent.sh --payload DIR [--state DIR] [--uninstall]
#
# The payload must hold agentd, enc.key, config.toml and coordinator.pub. Include
# an enrolment.grant unless this host already has an agent.key.
set -eu
payload=""
state=""
uninstall=0
while [ $# -gt 0 ]; do
  case "$1" in
    --payload) payload=${2:?}; shift 2 ;;
    --state) state=${2:?}; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    *) echo "usage: $0 --payload DIR [--state DIR] [--uninstall]" >&2; exit 2 ;;
  esac
done
unit_dir=/etc/systemd/system
record=/opt/agent-fleet/unit.path

if [ "$uninstall" = 1 ]; then
  if [ -f "$record" ]; then
    unit=$(cat "$record")
    systemctl disable --now "$(basename "$unit" .service)" 2>/dev/null || true
    rm -f "$unit" "$record"
    systemctl daemon-reload 2>/dev/null || true
  fi
  printf 'uninstalled; state kept\n'
  exit 0
fi

[ -n "$payload" ] || { echo "--payload is required" >&2; exit 2; }
for file in agentd config.toml coordinator.pub; do
  [ -f "$payload/$file" ] || { echo "payload missing $file" >&2; exit 2; }
done

# Random instance and state names; the launcher hides the rotating binary name.
[ -n "$state" ] || state="/var/lib/.af-$(openssl rand -hex 4)"
binary="/opt/agent-fleet/.af-$(openssl rand -hex 4)"
service="af-$(openssl rand -hex 3)"
unit="$unit_dir/$service.service"
id -u agentfleet >/dev/null 2>&1 ||
  useradd --system --home "$state" --shell /usr/sbin/nologin agentfleet
install -d -m 0755 /opt/agent-fleet
install -o root -g root -m 0755 "$payload/agentd" "$binary"
printf '%s\n' "$binary" > /opt/agent-fleet/seed.path
install -d -o agentfleet -g agentfleet -m 0700 "$state"
for file in enc.key config.toml coordinator.pub agent.key enrolment.grant; do
  [ -f "$payload/$file" ] && install -o agentfleet -g agentfleet -m 0600 "$payload/$file" "$state/$file"
done

cat > /opt/agent-fleet/af-run <<EOF
#!/bin/sh
bin=\$(cat /opt/agent-fleet/seed.path 2>/dev/null)
[ -x "\$bin" ] || bin=\$(ls -t /opt/agent-fleet/.af-* 2>/dev/null | head -1)
exec "\$bin" --worker --state $state
EOF
chmod 0755 /opt/agent-fleet/af-run
printf '%s\n' "$unit" > "$record"
cat > "$unit" <<EOF
[Unit]
Description=Agent Fleet worker
After=network-online.target
[Service]
User=agentfleet
ExecStart=/opt/agent-fleet/af-run
Restart=always
RestartSec=5
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=45
[Install]
WantedBy=multi-user.target
EOF
if command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null; then
  systemctl enable --now "$service" || true
else
  printf 'systemctl unavailable; unit written to %s\n' "$unit"
fi
printf 'installed; state %s; unit %s\n' "$state" "$unit"
