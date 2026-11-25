#!/usr/bin/env bash
# Java4Shell (CVE-2026-114938) PoC runner
# Requirements:
#   - x86-64 CPU with AVX-512 VBMI (Intel Ice Lake+ / AMD Zen 4+)
#   - OpenJDK 17.0.6 or newer
#
# Usage: ./run.sh [path-to-java]

set -euo pipefail

JAVA="${1:-java}"

echo "=== Environment ==="
uname -a
"$JAVA" -version 2>&1
echo

# Check architecture
ARCH=$(uname -m)
if [[ "$ARCH" != "x86_64" ]]; then
    echo "SKIP: This machine is $ARCH. The bug requires x86-64 with AVX-512 VBMI."
    exit 2
fi

# Check AVX-512 VBMI on Linux
if [[ -f /proc/cpuinfo ]]; then
    REQUIRED=(avx512f avx512bw avx512vbmi bmi2)
    MISSING=()
    for flag in "${REQUIRED[@]}"; do
        if ! grep -qm1 "$flag" /proc/cpuinfo; then
            MISSING+=("$flag")
        fi
    done
    if [[ ${#MISSING[@]} -gt 0 ]]; then
        echo "SKIP: CPU missing required flags: ${MISSING[*]}"
        exit 2
    fi
    echo "CPU flags OK: ${REQUIRED[*]}"
fi

echo
echo "=== Compiling ==="
"$JAVA"c Base64Trigger.java
echo "OK"

echo
echo "=== Running PoC ==="
"$JAVA" Base64Trigger
