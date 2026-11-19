#!/bin/sh
# Verifies a release directory against its Ed25519 signature.
#
#   scripts/verify-release.sh RELEASE_DIR [PUBKEY]
set -eu
dir=${1:?usage: verify-release.sh RELEASE_DIR [PUBKEY]}
pub=""
if [ -n "${2:-}" ]; then
  pub=$(readlink -f "$2")
fi
cd "$dir"
pub=${pub:-agent-fleet-signing.pub}
openssl pkeyutl -verify -rawin -pubin -inkey "$pub" \
  -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c SHA256SUMS
printf 'release verified\n'
