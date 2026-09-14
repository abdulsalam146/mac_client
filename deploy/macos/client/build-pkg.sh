#!/bin/bash
# W30 step 8 (plan §3.8): build the UNSIGNED dev .pkg on a macOS host.
# Payload + scriptlet semantics mirror the Linux .deb/.rpm exactly:
# never owns /var/lib/aztna-client (state survives upgrades), bootstrap
# on install, bootout on remove. Signing/notarization = owner gate
# (owner-to-production §3.5 — release VERIFICATION, not packaging).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="${AZTNA_REPO:-$(cd "$HERE/../../.." && pwd)}"
VERSION="${1:-0.30.0}"
OUT="${2:-$HERE/aztna-client.pkg}"
STAGE="$(mktemp -d)/root"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT
mkdir -p "$STAGE/usr/local/aztna/bin" "$STAGE/Library/LaunchDaemons"
BIN_DIR="${AZTNA_PKG_BIN_DIR:-target/release}"
cp "$REPO_ROOT/$BIN_DIR/glmsvc" "$STAGE/usr/local/aztna/bin/"
cp "$REPO_ROOT/$BIN_DIR/glmcli" "$STAGE/usr/local/aztna/bin/"
chmod 0755 "$STAGE/usr/local/aztna/bin/"*
cp "$HERE/com.aztna.client.plist" "$STAGE/Library/LaunchDaemons/"
chmod 0644 "$STAGE/Library/LaunchDaemons/com.aztna.client.plist"
pkgbuild \
    --root "$STAGE" \
    --scripts "$HERE/scripts" \
    --identifier com.aztna.client \
    --version "$VERSION" \
    --ownership recommended \
    "$OUT"
echo "built $OUT (unsigned dev artifact)"
