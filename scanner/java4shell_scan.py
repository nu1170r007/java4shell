#!/usr/bin/env python3
"""Java4Shell (CVE-2026-114938) Network Scanner

Probes remote hosts to detect vulnerable Java versions via:
  1. HTTP Server header analysis
  2. SSH banner grabbing (JDK version in JMXRMI, etc.)
  3. TLS certificate fingerprinting for Java-based services

Usage:
    python3 java4shell_scan.py --targets hosts.txt
    python3 java4shell_scan.py --cidr 10.0.0.0/24 --ports 8080,8443,443
    echo "app.example.com" | python3 java4shell_scan.py --stdin
"""

import argparse
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VULN_RANGES = {
    17: {"min_patch": 6, "max_patch": 21},
    21: {"min_patch": 0, "max_patch": 13},
    25: {"min_patch": 0, "max_patch": 5},
    27: {"min_patch": 0, "max_patch": 1},
}

JAVA_SIGNATURES = [
    re.compile(r"(?:OpenJDK|Java|Temurin|Corretto|Zulu|GraalVM)[/ ]*([\d.]+)", re.I),
    re.compile(r"X-Powered-By:.*Java/([\d.]+)", re.I),
    re.compile(r"Server:.*(?:Jetty|Tomcat|WildFly|Undertow|GlassFish)", re.I),
]

DEFAULT_PORTS = [80, 443, 8080, 8443, 8081, 9200, 9090, 7990, 8090, 8888]


def parse_version(version_str):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", version_str):
        return None
    parts = version_str.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        update = int(parts[3]) if len(parts) > 3 else 0
        return major, minor, patch, update
    except (ValueError, IndexError):
        return None


def is_vulnerable(major, minor, patch, update=0):
    if major not in VULN_RANGES:
        return None
    r = VULN_RANGES[major]
    return minor == 0 and r["min_patch"] <= patch and (patch, update) < (r["max_patch"], 1)


def probe_http(host, port, timeout=5):
    findings = []
    for scheme in ("https", "http") if port in (443, 8443) else ("http", "https"):
        try:
            url = f"{scheme}://{host}:{port}/"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "java4shell-scanner/1.0")
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                headers = str(resp.headers)
                for pattern in JAVA_SIGNATURES:
                    m = pattern.search(headers)
                    if m:
                        findings.append({
                            "source": "http_header",
                            "url": url,
                            "match": m.group(0),
                            "version": m.group(1) if m.lastindex else None,
                        })
                break
        except Exception:
            continue
    return findings


def probe_tls(host, port, timeout=5):
    findings = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    issuer = str(cert.get("issuer", ""))
                    subject = str(cert.get("subject", ""))
                    if any(kw in issuer + subject for kw in ("Java", "JKS", "keytool")):
                        findings.append({
                            "source": "tls_cert",
                            "detail": "Java keytool-generated certificate detected",
                        })
    except Exception:
        pass
    return findings


def probe_banner(host, port, timeout=3):
    findings = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(1024).decode("utf-8", errors="replace")
            for pattern in JAVA_SIGNATURES:
                m = pattern.search(banner)
                if m:
                    findings.append({
                        "source": "banner",
                        "match": m.group(0),
                        "version": m.group(1) if m.lastindex else None,
                    })
    except Exception:
        pass
    return findings


def scan_host(host, ports, timeout=5):
    results = {"host": host, "ports": {}, "vulnerable": None, "candidate": False,
               "assessment": "INCONCLUSIVE", "java_detected": False}

    for port in ports:
        port_results = []
        port_results.extend(probe_http(host, port, timeout))
        port_results.extend(probe_tls(host, port, timeout))
        if not port_results:
            port_results.extend(probe_banner(host, port, timeout))

        if port_results:
            results["ports"][port] = port_results
            results["java_detected"] = True
            for finding in port_results:
                ver_str = finding.get("version")
                if ver_str:
                    parsed = parse_version(ver_str)
                    match = is_vulnerable(*parsed) if parsed else None
                    if match is True:
                        finding["status"] = "VERSION_CANDIDATE"
                        results["candidate"] = True
                        results["assessment"] = "CANDIDATE"
                    elif match is False:
                        finding["status"] = "OUTSIDE_KNOWN_RANGE"
                    else:
                        finding["status"] = "UNKNOWN"
                else:
                    finding["status"] = "UNKNOWN"

    return results


def load_targets(args):
    targets = []
    if args.targets:
        with open(args.targets) as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    if args.cidr:
        for cidr in args.cidr.split(","):
            for ip in ipaddress.ip_network(cidr.strip(), strict=False):
                targets.append(str(ip))
    if args.host:
        targets.extend(args.host.split(","))
    if args.stdin:
        targets.extend(line.strip() for line in sys.stdin if line.strip())
    return list(dict.fromkeys(targets))


def main():
    parser = argparse.ArgumentParser(description="Java4Shell (CVE-2026-114938) Network Scanner")
    parser.add_argument("--host", help="Comma-separated hosts")
    parser.add_argument("--targets", help="File with target hosts (one per line)")
    parser.add_argument("--cidr", help="CIDR range(s) to scan")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                        help=f"Ports to scan (default: {','.join(map(str, DEFAULT_PORTS))})")
    parser.add_argument("--threads", type=int, default=20, help="Concurrent threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout (default: 5s)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        sys.exit(1)

    ports = [int(p) for p in args.ports.split(",")]

    if not args.json:
        print(f"╔═══════════════════════════════════════════════════╗")
        print(f"║  Java4Shell (CVE-2026-114938) Network Scanner     ║")
        print(f"╚═══════════════════════════════════════════════════╝")
        print(f"\nTargets: {len(targets)}  Ports: {args.ports}  Threads: {args.threads}\n")

    all_results = []
    vuln_count = 0

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, t, ports, args.timeout): t for t in targets}
        for future in as_completed(futures):
            result = future.result()
            all_results.append(result)
            if not args.json:
                if result["candidate"]:
                    vuln_count += 1
                    print(f"  CANDIDATE  {result['host']} — version hint only")
                    for port, findings in result["ports"].items():
                        for f in findings:
                            status = f.get("status", "")
                            ver = f.get("version", "unknown")
                            print(f"         :{port} — {f['source']}: {f.get('match', '')} [{status}]")
                else:
                    print(f"  INCONCLUSIVE  {result['host']} — no confirmed runtime assessment")

    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        print(f"\n{'═' * 51}")
        print(f"Scanned: {len(targets)}  Java hints: {sum(1 for r in all_results if r['java_detected'])}  Candidates: {vuln_count}")
        print("Network hints cannot verify guest CPU flags, effective JVM flags or vendor backports.")


if __name__ == "__main__":
    main()
