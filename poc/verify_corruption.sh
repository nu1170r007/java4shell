#!/usr/bin/env bash
# Local bounded verification only; never attaches to an application JVM.
set -euo pipefail
JAVA="${1:-java}"
DIR="$(cd "$(dirname "$0")" && pwd)"
command -v timeout >/dev/null || { echo "INCONCLUSIVE: timeout is required"; exit 2; }
JAVA=$(command -v "$JAVA") || { echo "INCONCLUSIVE: Java unavailable"; exit 2; }
JAVAC="${JAVA}c"
[[ -x "$JAVAC" ]] || { echo "INCONCLUSIVE: matching javac unavailable"; exit 2; }
[[ "$(uname -m)" == x86_64 ]] || { echo "SKIP: requires x86-64"; exit 2; }
flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null || true)
for flag in avx512f avx512bw avx512vbmi bmi2; do
    [[ " $flags " == *" $flag "* ]] || { echo "SKIP: missing or unreadable CPU flag $flag"; exit 2; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if ! timeout 30 "$JAVAC" "$DIR/Base64Trigger.java" -d "$work" >"$work/compile.log" 2>&1; then
    echo "INCONCLUSIVE: compilation failed or timed out"
    exit 2
fi

run_probe() {
    local code=0
    timeout 60 "$JAVA" "$@" -cp "$work" Base64Trigger >"$work/output" 2>&1 || code=$?
    # Never print raw JVM output: inherited options may contain credentials.
    if [[ $code -eq 0 ]] && grep -qx REPRODUCED "$work/output"; then
        result=REPRODUCED
    elif [[ $code -eq 1 ]] && grep -qx 'NOT REPRODUCED' "$work/output" &&
         grep -qx 'rejected=true changed=0 first=-1 last=-1' "$work/output"; then
        result=NOT_REPRODUCED
    else
        result=INCONCLUSIVE
    fi
    echo "$result"
}

echo "Default test (inherits this shell's JVM options):"
run_probe
if [[ "$result" != REPRODUCED ]]; then
    echo "INCONCLUSIVE: a negative test does not establish patch status or service safety"
    exit 2
fi
echo "Mitigation control (-XX:-UseBASE64Intrinsics):"
run_probe -XX:-UseBASE64Intrinsics
if [[ "$result" != NOT_REPRODUCED ]]; then
    echo "INCONCLUSIVE: mitigation control failed"
    exit 2
fi
echo "CONFIRMED: tested runtime reproduced corruption; separate mitigated process did not"
echo "The running application's configuration has NOT been verified."
exit 1
