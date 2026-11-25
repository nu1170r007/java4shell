#!/usr/bin/env bash
# Java4Shell (CVE-2026-114938) Host Scanner
# Checks all Java installations on the host for vulnerability
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Java4Shell (CVE-2026-114938) Host Scanner    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
echo

VULN_COUNT=0
SAFE_COUNT=0
SKIP_COUNT=0
UNKNOWN_COUNT=0

check_cpu() {
    local arch
    arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        echo -e "${GREEN}[+] CPU: $arch — NOT AFFECTED (AVX-512 VBMI is x86-64 only)${NC}"
        exit 0
    fi

    if [[ -f /proc/cpuinfo ]]; then
        local flag
        local flags
        flags=$(grep -m1 '^flags' /proc/cpuinfo || true)
        if [[ -z "$flags" ]]; then
            echo "UNKNOWN: cannot read guest CPU flags"
            exit 2
        fi
        for flag in avx512f avx512bw avx512vbmi bmi2; do
            if [[ " $flags " != *" $flag "* ]]; then
                echo "HARDWARE_NOT_AFFECTED: guest CPU lacks $flag (current placement only)"
                exit 0
            fi
        done
        local cpu_name
        cpu_name=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
        echo -e "${YELLOW}[!] CPU: $cpu_name — all four required guest flags present${NC}"
        return 0
    else
        echo "UNKNOWN: cannot inspect CPU flags"
        exit 2
    fi
}

check_java() {
    local java_bin="$1"
    local version_output
    if ! version_output=$(timeout 15 "$java_bin" -version 2>&1); then
        echo "    UNKNOWN  $java_bin — version command failed or timed out"
        ((UNKNOWN_COUNT+=1))
        return
    fi

    local version
    version=$(sed -nE 's/.*version "([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)([^0-9.].*)?".*/\1/p' <<< "$version_output" | head -1)
    if [[ -z "$version" ]]; then
        echo "    UNKNOWN  $java_bin — unsupported version format"
        ((UNKNOWN_COUNT+=1))
        return
    fi
    local major minor patch update
    IFS=. read -r major minor patch update <<< "$version"
    update=${update:-0}

    local vm_name
    vm_name=$(echo "$version_output" | grep -i 'vm' | head -1 || true)

    local vulnerable=false

    local known=false boundary=0 lower=0
    case "$major" in
        17)
            known=true; boundary=21; lower=6
            ;;
        21)
            known=true; boundary=13
            ;;
        25)
            known=true; boundary=5
            ;;
        27)
            known=true; boundary=1
            ;;
    esac
    if $known && (( minor == 0 && patch >= lower && (patch < boundary || (patch == boundary && update == 0)) )); then
        vulnerable=true
    fi

    # Check for OpenJ9 (not affected)
    if echo "$vm_name" | grep -qi 'openj9\|j9'; then
        echo -e "    ${GREEN}RUNTIME_NOT_AFFECTED${NC}  $java_bin"
        echo -e "          $version — OpenJ9 (different runtime, not affected)"
        ((SAFE_COUNT++)) || true
        return
    fi

    if ! $known; then
        echo "    UNKNOWN  $java_bin — unsupported version family $version"
        ((UNKNOWN_COUNT+=1))
    elif $vulnerable; then
        echo -e "    ${RED}CANDIDATE${NC}  $java_bin"
        echo -e "          $version — verify vendor backports and the active runtime"
        ((VULN_COUNT++)) || true
    else
        echo -e "    ${YELLOW}OUTSIDE_KNOWN_RANGE${NC}  $java_bin"
        echo -e "          $version — verify vendor advisory; not a service clearance"
        ((SAFE_COUNT++)) || true
    fi
}

check_jvm_flags() {
    local pid="$1"
    local java_bin jcmd flags
    java_bin=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
    jcmd="${java_bin%/*}/jcmd"
    if [[ -x "$jcmd" ]] && flags=$(timeout 15 "$jcmd" "$pid" VM.flags -all 2>/dev/null); then
        if grep -Eq 'bool[[:space:]]+UseBASE64Intrinsics[[:space:]]+=[[:space:]]+false([[:space:]]|$)' <<< "$flags"; then
            echo "    MITIGATED  PID $pid — effective UseBASE64Intrinsics=false"
        elif grep -Eq 'bool[[:space:]]+UseBASE64Intrinsics[[:space:]]+=[[:space:]]+true([[:space:]]|$)' <<< "$flags"; then
            echo "    INTRINSIC_ENABLED  PID $pid — verify vendor patch and CPU eligibility"
        else
            echo "    UNKNOWN  PID $pid — effective Base64 flag unavailable"
            ((UNKNOWN_COUNT+=1))
        fi
    else
        echo "    UNKNOWN  PID $pid — cannot read effective flags (permissions, namespace or missing jcmd)"
        ((UNKNOWN_COUNT+=1))
    fi
}

main() {
command -v timeout >/dev/null || { echo "UNKNOWN: timeout is required"; return 2; }
# 1. CPU check
echo -e "${BLUE}[1/3] CPU Check${NC}"
check_cpu
echo

# 2. Find all Java binaries
echo -e "${BLUE}[2/3] Java Installations${NC}"
JAVA_BINS=()

# Common paths
for path in \
    /usr/bin/java /usr/local/bin/java \
    /usr/lib/jvm/*/bin/java \
    /usr/java/*/bin/java \
    /opt/java/*/bin/java \
    /opt/jdk*/bin/java \
    /nix/store/*/bin/java \
    /nix/store/*/lib/openjdk/bin/java \
    /Library/Java/JavaVirtualMachines/*/Contents/Home/bin/java; do
    [[ -x "$path" ]] && JAVA_BINS+=("$path")
done

# JAVA_HOME
[[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/java" ]] && JAVA_BINS+=("$JAVA_HOME/bin/java")

# which java
command -v java &>/dev/null && JAVA_BINS+=("$(command -v java)")
for exe in /proc/[0-9]*/exe; do
    resolved=$(readlink -f "$exe" 2>/dev/null || true)
    [[ "${resolved##*/}" == java && -x "$resolved" ]] && JAVA_BINS+=("$resolved")
done
for path in "$@"; do
    if [[ -x "$path" ]]; then
        JAVA_BINS+=("$path")
    else
        echo "    UNKNOWN  explicit Java path unavailable: $path"
        ((UNKNOWN_COUNT+=1))
    fi
done

# Deduplicate
readarray -t JAVA_BINS < <(printf '%s\n' "${JAVA_BINS[@]}" | sed '/^$/d' | sort -u)

if [[ ${#JAVA_BINS[@]} -eq 0 ]]; then
    echo "    UNKNOWN: no Java installations found in the visible filesystem"
    ((UNKNOWN_COUNT+=1))
else
    for jbin in "${JAVA_BINS[@]}"; do
        check_java "$jbin"
    done
fi
echo

# 3. Running JVMs
echo -e "${BLUE}[3/3] Running JVM Processes${NC}"
JAVA_PIDS=$(pgrep -x java 2>/dev/null || true)
if [[ -z "$JAVA_PIDS" ]]; then
    echo "    No running JVM processes found"
else
    while read -r pid; do
        [[ -n "$pid" ]] && check_jvm_flags "$pid"
    done <<< "$JAVA_PIDS"
fi
echo

# Summary
echo "═══════════════════════════════════════════════"
if [[ $VULN_COUNT -gt 0 ]]; then
    echo -e "${RED}RESULT: $VULN_COUNT candidates, $SAFE_COUNT outside range/other runtime, $UNKNOWN_COUNT unknown${NC}"
    echo
    echo "Recommended actions:"
    echo "  1. Update to fixed JDK (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1)"
    echo "  2. Interim: add -XX:-UseBASE64Intrinsics to all JVM start flags"
    echo "  3. Restart all JVM processes after patching"
    exit 1
elif [[ $UNKNOWN_COUNT -gt 0 ]]; then
    echo "RESULT: INCONCLUSIVE — $UNKNOWN_COUNT unknown checks"
    exit 2
else
    echo "RESULT: No candidates in discovered installations; containers and undiscovered runtimes are not cleared"
    exit 0
fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
