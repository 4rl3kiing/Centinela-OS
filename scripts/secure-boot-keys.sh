#!/usr/bin/env bash
# Generates a TEST-ONLY Secure Boot key hierarchy (PK, KEK, db) for CI and
# local QEMU runs. Production signing keys must be generated and held
# offline by the release owner; never commit private keys.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYS="${SB_KEY_DIR:-$ROOT/build/sb-keys}"
mkdir -p "$KEYS"
chmod 700 "$KEYS"
for name in PK KEK db wrong-db; do
    if [[ ! -f "$KEYS/$name.key" ]]; then
        openssl req -quiet -newkey rsa:2048 -nodes -keyout "$KEYS/$name.key" -new -x509 -sha256 \
            -days 30 -subj "/CN=Centinela-OS TEST $name (not for production)/" -out "$KEYS/$name.crt" 2>/dev/null
        chmod 600 "$KEYS/$name.key"
    fi
done
echo "Test Secure Boot keys in $KEYS"
