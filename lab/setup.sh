#!/usr/bin/env bash
# Java4Shell Lab — One-click setup
set -euo pipefail

cd "$(dirname "$0")"

echo "╔═══════════════════════════════════════════════╗"
echo "║  Java4Shell Lab Setup                         ║"
echo "╚═══════════════════════════════════════════════╝"
echo

ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    echo "⚠  WARNING: This machine is $ARCH."
    echo "   The vulnerability requires x86-64 with AVX-512 VBMI."
    echo "   The lab will build but the PoC will NOT reproduce."
    echo
fi

echo "[*] Building lab environment..."
docker compose build

echo "[*] Starting containers..."
docker compose up -d

echo
echo "[+] Lab is running. Enter the PoC container:"
echo "    docker compose exec poc bash"
echo
echo "[+] Inside the container, run:"
echo "    java Base64Trigger"
echo
echo "[+] Test mitigation:"
echo "    java -XX:-UseBASE64Intrinsics Base64Trigger"
echo
echo "[*] To stop: docker compose down"
