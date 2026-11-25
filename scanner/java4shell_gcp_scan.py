#!/usr/bin/env python3
"""Java4Shell (CVE-2026-114938) GCP Estate Scanner

Inventories every GCP project the caller can see and reports Java4Shell
exposure using read-only APIs (via the gcloud / kubectl CLIs):

  1. Projects            - all ACTIVE projects (optionally filtered by org/folder)
  2. Compute Engine      - every VM (incl. GKE nodes): actual CPU platform ->
                           AVX-512 VBMI eligibility, external IPs
  3. GKE                 - clusters, node pools, Autopilot flag
  4. Kubernetes (opt-in) - running pods and container images; Java-looking
                           images are flagged
  5. In-container (opt-in, --exec-check) - read-only probe inside running
                           containers: JVM version, guest CPU flags and the
                           effective UseBASE64Intrinsics value (via jcmd)
  6. Cloud Run           - services and images (Google-managed hardware)
  7. Network (opt-in, --network-probe) - runs the passive HTTP/TLS/banner
                           probes from java4shell_scan.py against the
                           project's own external IPs and forwarding rules

Nothing here sends a Base64 payload or attempts exploitation. Like the other
scanners in this repo, results are triage hints: no finding ever clears a
host, and hardware exclusions apply only to the current placement.

Required (read-only) permissions on each project:
  roles/browser (projects.list), roles/serviceusage.serviceUsageViewer,
  roles/compute.viewer, roles/container.viewer, roles/run.viewer
  --exec-check additionally needs container.pods.exec (e.g. roles/container.developer)
Usage:
    python3 java4shell_gcp_scan.py                         # all visible projects
    python3 java4shell_gcp_scan.py --org 123456789012      # one organization
    python3 java4shell_gcp_scan.py --projects p1,p2 --k8s --exec-check
    python3 java4shell_gcp_scan.py --network-probe --out report
"""

import argparse
import csv
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# Reuse version logic and passive network probes from the existing scanner.
_spec = importlib.util.spec_from_file_location(
    "java4shell_scan", Path(__file__).resolve().parent / "java4shell_scan.py")
netscan = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(netscan)

PRINT_LOCK = threading.Lock()
LOG_QUIET = False

# --------------------------------------------------------------------------- #
# CPU platform classification
# --------------------------------------------------------------------------- #
# GCE reports the actual host platform in instance.cpuPlatform.
VBMI_PLATFORMS = ("ice lake", "sapphire rapids", "emerald rapids", "granite rapids",
                  "genoa", "bergamo", "turin")
NO_VBMI_PLATFORMS = ("sandy bridge", "ivy bridge", "haswell", "broadwell", "skylake",
                     "cascade lake", "naples", "rome", "milan")
ARM_PLATFORMS = ("ampere", "axion", "arm", "neoverse")
# Families whose platform can change across restarts/migrations.
VARIABLE_FAMILIES = ("e2", "n2", "n2d", "n1", "f1", "g1")

HW_ELIGIBLE = "HARDWARE_ELIGIBLE"
HW_NOT_AFFECTED = "HARDWARE_NOT_AFFECTED"
HW_UNKNOWN = "HARDWARE_UNKNOWN"

JAVA_IMAGE_HINTS = re.compile(
    r"(jdk|jre|java|openjdk|temurin|corretto|zulu|graalvm|liberica|semeru|"
    r"jenkins|keycloak|elasticsearch|opensearch|kafka|solr|zookeeper|gerrit|"
    r"spinnaker|tomcat|jetty|wildfly|spring|confluence|jira|artifactory|"
    r"nexus|sonarqube|pingfederate|forgerock|cassandra|flink|spark|trino)",
    re.I)


def log(msg):
    if not LOG_QUIET:
        with PRINT_LOCK:
            print(msg, file=sys.stderr, flush=True)


def classify_cpu(cpu_platform, machine_type=""):
    """Return (hardware_status, note) for a GCE cpuPlatform string."""
    p = (cpu_platform or "").lower()
    family = (machine_type or "").split("/")[-1].split("-")[0].lower()
    variable = family in VARIABLE_FAMILIES

    if any(k in p for k in ARM_PLATFORMS):
        return HW_NOT_AFFECTED, "ARM CPU (x86-64 only flaw)"
    if any(k in p for k in VBMI_PLATFORMS):
        return HW_ELIGIBLE, "CPU generation supports AVX-512 VBMI"
    if any(k in p for k in NO_VBMI_PLATFORMS):
        note = "CPU generation lacks AVX-512 VBMI (current placement only)"
        if variable:
            note += f"; {family} VMs can land on other platforms after restart"
        return HW_NOT_AFFECTED, note
    return HW_UNKNOWN, f"unrecognized or unavailable platform '{cpu_platform or 'n/a'}'"


# --------------------------------------------------------------------------- #
# CLI helpers
# --------------------------------------------------------------------------- #
class CliError(Exception):
    pass


def run_json(cmd, timeout=120, env=None):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise CliError(f"timeout: {' '.join(cmd[:4])}")
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        raise CliError(err[-1] if err else f"exit {proc.returncode}")
    out = proc.stdout.strip()
    return json.loads(out) if out else []


def gcloud(args, project=None, timeout=120):
    cmd = ["gcloud", *args, "--format=json", "--quiet"]
    if project:
        cmd.append(f"--project={project}")
    return run_json(cmd, timeout=timeout)


# --------------------------------------------------------------------------- #
# Enumeration
# --------------------------------------------------------------------------- #
def list_projects(args):
    if args.projects:
        return [{"projectId": p.strip(), "name": p.strip()} for p in args.projects.split(",") if p.strip()]
    filters = ["lifecycleState:ACTIVE"]
    if args.org:
        filters.append(f"parent.type:organization parent.id:{args.org}")
    if args.folder:
        filters.append(f"parent.type:folder parent.id:{args.folder}")
    if args.filter:
        filters.append(args.filter)
    projects = gcloud(["projects", "list", f"--filter={' '.join(filters)}"])
    if args.exclude:
        excluded = re.compile(args.exclude)
        projects = [p for p in projects if not excluded.search(p["projectId"])]
    return projects


def enabled_services(project):
    try:
        services = gcloud(["services", "list", "--enabled"], project=project)
    except CliError:
        return None  # cannot tell; try each API anyway
    return {s.get("config", {}).get("name") for s in services}


def scan_compute(project):
    instances = []
    for inst in gcloud(["compute", "instances", "list"], project=project, timeout=300):
        machine_type = inst.get("machineType", "").split("/")[-1]
        cpu_platform = inst.get("cpuPlatform", "")
        hw, note = classify_cpu(cpu_platform, machine_type)
        labels = inst.get("labels", {}) or {}
        ext_ips = [ac.get("natIP") for ni in inst.get("networkInterfaces", [])
                   for ac in ni.get("accessConfigs", []) if ac.get("natIP")]
        int_ips = [ni.get("networkIP") for ni in inst.get("networkInterfaces", []) if ni.get("networkIP")]
        instances.append({
            "project": project,
            "name": inst.get("name"),
            "zone": inst.get("zone", "").split("/")[-1],
            "status": inst.get("status"),
            "machine_type": machine_type,
            "cpu_platform": cpu_platform,
            "min_cpu_platform": inst.get("minCpuPlatform"),
            "hardware": hw,
            "hardware_note": note,
            "gke_cluster": labels.get("goog-k8s-cluster-name"),
            "external_ips": ext_ips,
            "internal_ips": int_ips,
        })
    return instances


def scan_gke(project):
    clusters = []
    for c in gcloud(["container", "clusters", "list"], project=project):
        clusters.append({
            "project": project,
            "name": c.get("name"),
            "location": c.get("location"),
            "version": c.get("currentMasterVersion"),
            "autopilot": bool((c.get("autopilot") or {}).get("enabled")),
            "private_endpoint": bool((c.get("privateClusterConfig") or {}).get("enablePrivateEndpoint")),
            "node_pools": [{
                "name": np.get("name"),
                "machine_type": (np.get("config") or {}).get("machineType"),
                "min_cpu_platform": (np.get("config") or {}).get("minCpuPlatform"),
                "node_count": np.get("initialNodeCount"),
            } for np in c.get("nodePools", []) or []],
        })
    return clusters


def scan_cloud_run(project):
    services = []
    for s in gcloud(["run", "services", "list"], project=project):
        containers = (((s.get("spec") or {}).get("template") or {}).get("spec") or {}).get("containers", [])
        for ct in containers:
            image = ct.get("image", "")
            services.append({
                "project": project,
                "service": (s.get("metadata") or {}).get("name"),
                "region": ((s.get("metadata") or {}).get("labels") or {}).get("cloud.googleapis.com/location"),
                "image": image,
                "java_image_hint": bool(JAVA_IMAGE_HINTS.search(image)),
                "url": (s.get("status") or {}).get("url"),
            })
    return services


def scan_forwarding_rules(project):
    return [{"project": project, "name": r.get("name"), "ip": r.get("IPAddress"),
             "ports": r.get("portRange") or ",".join(r.get("ports", []) or []),
             "scheme": r.get("loadBalancingScheme")}
            for r in gcloud(["compute", "forwarding-rules", "list"], project=project)
            if r.get("loadBalancingScheme", "").startswith("EXTERNAL")]


# --------------------------------------------------------------------------- #
# Kubernetes inventory and in-container probe
# --------------------------------------------------------------------------- #
# POSIX sh only: shell builtins plus readlink, so it works in slim images.
# Prints JVM version banners, guest CPU flags and the effective Base64 flag.
# When jcmd is absent (typical JRE images) it reports only whether the
# mitigation flag appears in the process command line or environment
# (e.g. JAVA_TOOL_OPTIONS); the command line itself is never printed.
PROBE_SCRIPT = r'''
echo "@@ARCH $(uname -m 2>/dev/null)"
if [ -r /proc/cpuinfo ]; then
  while IFS= read -r l; do case "$l" in flags*) echo "@@CPU $l"; break;; esac; done < /proc/cpuinfo
fi
for p in /proc/[0-9]*; do
  e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in
    */java)
      pid=${p#/proc/}
      v=$( (unset JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS; "$e" -version 2>&1) | { n=0; while IFS= read -r x && [ $n -lt 3 ]; do case "$x" in *"Picked up"*) continue;; esac; printf '%s;' "$x"; n=$((n+1)); done; })
      echo "@@JVM $pid|$e|$v"
      if command -v grep >/dev/null 2>&1; then
        if grep -q -e '-XX:-UseBASE64Intrinsics' -e '-XX:UseAVX=[012]' "/proc/$pid/cmdline" "/proc/$pid/environ" 2>/dev/null; then
          echo "@@HINT $pid|disabled"
        else
          echo "@@HINT $pid|none"
        fi
      fi
      j="${e%/*}/jcmd"
      if [ -x "$j" ]; then
        "$j" "$pid" VM.flags -all 2>/dev/null | while IFS= read -r f; do
          case "$f" in *UseBASE64Intrinsics*) echo "@@FLAG $pid|$f";; esac
        done
      fi;;
  esac
done
echo "@@END"
'''

VERSION_RE = re.compile(r'version "(\d+\.\d+\.\d+(?:\.\d+)?)')


def parse_probe_output(text):
    """Turn PROBE_SCRIPT output into an assessment per JVM."""
    arch, cpu_flags, cpu_read = "", set(), False
    jvms, flags, hints = {}, {}, {}
    complete = False
    for line in text.splitlines():
        if line.startswith("@@ARCH "):
            arch = line[7:].strip()
        elif line.startswith("@@CPU "):
            cpu_read = True
            cpu_flags = set(line.split(":", 1)[-1].split())
        elif line.startswith("@@JVM "):
            pid, path, banner = (line[6:].split("|", 2) + ["", ""])[:3]
            jvms[pid] = {"pid": pid, "path": path, "banner": banner.strip(";")}
        elif line.startswith("@@FLAG "):
            pid, flag = (line[7:].split("|", 1) + [""])[:2]
            m = re.search(r"UseBASE64Intrinsics\s*=\s*(true|false)", flag)
            if m:
                flags[pid] = m.group(1)
        elif line.startswith("@@HINT "):
            pid, hint = (line[7:].split("|", 1) + [""])[:2]
            hints[pid] = hint.strip()
        elif line.strip() == "@@END":
            complete = True

    required = {"avx512f", "avx512bw", "avx512vbmi", "bmi2"}
    if arch and arch != "x86_64":
        cpu = "NOT_ELIGIBLE"
    elif cpu_read:
        cpu = "ELIGIBLE" if required <= cpu_flags else "NOT_ELIGIBLE"
    else:
        cpu = "UNKNOWN"

    results = []
    for pid, j in jvms.items():
        banner = j["banner"]
        m = VERSION_RE.search(banner)
        version = m.group(1) if m else None
        intrinsic = flags.get(pid)
        if re.search(r"openj9|\bj9\b", banner, re.I):
            status = "RUNTIME_NOT_AFFECTED"
        elif not version:
            status = "UNKNOWN"
        else:
            parsed = netscan.parse_version(version)
            in_range = netscan.is_vulnerable(*parsed) if parsed else None
            if in_range is None:
                status = "OUTSIDE_KNOWN_RANGE" if parsed and parsed[0] in (8, 11) else "UNKNOWN"
            elif not in_range:
                status = "OUTSIDE_KNOWN_RANGE"
            elif intrinsic == "false":
                status = "MITIGATED"
            elif intrinsic is None and hints.get(pid) == "disabled":
                status = "LIKELY_MITIGATED"
            elif cpu == "NOT_ELIGIBLE":
                status = "CANDIDATE_HW_NOT_ELIGIBLE"
            else:
                status = "CANDIDATE"
        results.append({**j, "version": version, "use_base64_intrinsics": intrinsic,
                        "flag_in_cmdline_or_env": hints.get(pid) == "disabled",
                        "cpu": cpu, "status": status})
    return {"arch": arch, "cpu": cpu, "complete": complete, "jvms": results}


def kubeconfig_for(cluster, args):
    fd, path = tempfile.mkstemp(prefix="kubeconfig-", suffix=".yaml")
    os.close(fd)
    env = dict(os.environ, KUBECONFIG=path)
    cmd = ["gcloud", "container", "clusters", "get-credentials", cluster["name"],
           f"--location={cluster['location']}", f"--project={cluster['project']}", "--quiet"]
    if args.internal_ip:
        cmd.append("--internal-ip")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    if proc.returncode != 0:
        os.unlink(path)
        raise CliError((proc.stderr or "get-credentials failed").strip().splitlines()[-1])
    return path, env


def exec_probe(env, ns, pod, container, timeout):
    cmd = ["kubectl", "exec", "-n", ns, pod, "-c", container, "--", "sh", "-c", PROBE_SCRIPT]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    if "@@ARCH" not in proc.stdout:
        err = (proc.stderr or "").strip().splitlines()
        return {"error": err[-1] if err else "no shell in container"}
    return parse_probe_output(proc.stdout)


def scan_k8s(cluster, args):
    out = {"cluster": cluster["name"], "project": cluster["project"], "containers": [], "error": None}
    try:
        path, env = kubeconfig_for(cluster, args)
    except CliError as e:
        out["error"] = f"credentials: {e}"
        return out
    try:
        pods = run_json(["kubectl", "get", "pods", "-A", "-o", "json",
                         f"--request-timeout={args.timeout}s"], timeout=180, env=env)
        targets = []
        for pod in pods.get("items", []):
            meta, spec, status = pod["metadata"], pod.get("spec", {}), pod.get("status", {})
            if status.get("phase") != "Running":
                continue
            ns = meta["namespace"]
            if ns in args.skip_namespaces:
                continue
            for c in spec.get("containers", []):
                rec = {"project": cluster["project"], "cluster": cluster["name"],
                       "namespace": ns, "pod": meta["name"], "container": c["name"],
                       "image": c.get("image", ""), "node": spec.get("nodeName"),
                       "java_image_hint": bool(JAVA_IMAGE_HINTS.search(c.get("image", ""))),
                       "probe": None}
                out["containers"].append(rec)
                if args.exec_check and (args.exec_all or rec["java_image_hint"]):
                    targets.append(rec)

        if targets:
            log(f"    [{cluster['name']}] probing {len(targets)} containers")
            with ThreadPoolExecutor(max_workers=args.exec_threads) as pool:
                futs = {pool.submit(exec_probe, env, r["namespace"], r["pod"], r["container"],
                                    args.timeout * 6): r for r in targets}
                for f in as_completed(futs):
                    futs[f]["probe"] = f.result()
    except CliError as e:
        out["error"] = f"kubectl: {e}"
    finally:
        os.unlink(path)
    return out


# --------------------------------------------------------------------------- #
# Per-project orchestration
# --------------------------------------------------------------------------- #
def scan_project(proj, args):
    pid = proj["projectId"]
    result = {"project": pid, "name": proj.get("name"), "errors": {},
              "instances": [], "gke_clusters": [], "k8s": [], "cloud_run": [],
              "forwarding_rules": [], "network": []}
    services = enabled_services(pid)

    def enabled(api):
        return services is None or api in services

    steps = [("compute", "compute.googleapis.com", scan_compute, "instances"),
             ("gke", "container.googleapis.com", scan_gke, "gke_clusters"),
             ("cloud_run", "run.googleapis.com", scan_cloud_run, "cloud_run")]
    if args.network_probe:
        steps.append(("forwarding_rules", "compute.googleapis.com", scan_forwarding_rules, "forwarding_rules"))

    for key, api, fn, field in steps:
        if not enabled(api):
            continue
        try:
            result[field] = fn(pid)
        except CliError as e:
            result["errors"][key] = str(e)

    if args.k8s or args.exec_check:
        for cluster in result["gke_clusters"]:
            result["k8s"].append(scan_k8s(cluster, args))

    if args.network_probe:
        hosts = {ip for i in result["instances"] for ip in i["external_ips"]}
        hosts |= {r["ip"] for r in result["forwarding_rules"] if r.get("ip")}
        ports = [int(p) for p in args.ports.split(",")]
        for host in sorted(hosts):
            result["network"].append(netscan.scan_host(host, ports, args.timeout))

    n_vm = len(result["instances"])
    n_el = sum(1 for i in result["instances"] if i["hardware"] == HW_ELIGIBLE)
    log(f"  [{pid}] VMs={n_vm} VBMI-eligible={n_el} GKE={len(result['gke_clusters'])} "
        f"CloudRun={len(result['cloud_run'])}"
        + (f" errors={list(result['errors'])}" if result["errors"] else ""))
    return result


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def flatten_findings(results):
    rows = []
    for r in results:
        for i in r["instances"]:
            rows.append({"project": r["project"], "type": "vm", "resource": i["name"],
                         "location": i["zone"], "detail": f"{i['machine_type']} / {i['cpu_platform']}",
                         "status": i["hardware"], "note": i["hardware_note"],
                         "exposure": "external" if i["external_ips"] else "internal"})
        for k in r["k8s"]:
            if k["error"]:
                rows.append({"project": r["project"], "type": "gke", "resource": k["cluster"],
                             "location": "", "detail": "", "status": "UNKNOWN", "note": k["error"],
                             "exposure": ""})
            for c in k["containers"]:
                probe = c.get("probe")
                base = {"project": r["project"], "type": "container",
                        "resource": f"{k['cluster']}/{c['namespace']}/{c['pod']}/{c['container']}",
                        "location": c.get("node") or "", "exposure": ""}
                if probe and probe.get("jvms"):
                    for j in probe["jvms"]:
                        rows.append({**base, "detail": f"{c['image']} | java {j['version']} "
                                                       f"| intrinsic={j['use_base64_intrinsics']} | cpu={j['cpu']}",
                                     "status": j["status"], "note": j["path"]})
                elif probe:
                    rows.append({**base, "detail": c["image"],
                                 "status": "UNKNOWN" if probe.get("error") else "NO_JVM_SEEN",
                                 "note": probe.get("error", "no running java process visible")})
                elif c["java_image_hint"]:
                    rows.append({**base, "detail": c["image"], "status": "JAVA_IMAGE_HINT",
                                 "note": "not probed (use --exec-check)"})
        for s in r["cloud_run"]:
            if s["java_image_hint"]:
                rows.append({"project": r["project"], "type": "cloud_run", "resource": s["service"],
                             "location": s["region"] or "", "detail": s["image"],
                             "status": "JAVA_IMAGE_HINT",
                             "note": "Google-managed hardware; patch the image JDK or set the JVM flag",
                             "exposure": "external" if s.get("url") else ""})
        for n in r["network"]:
            if n["java_detected"]:
                rows.append({"project": r["project"], "type": "network", "resource": n["host"],
                             "location": "", "detail": ",".join(map(str, n["ports"])),
                             "status": n["assessment"], "note": "passive banner hint only",
                             "exposure": "external"})
        for key, err in r["errors"].items():
            rows.append({"project": r["project"], "type": key, "resource": "", "location": "",
                         "detail": "", "status": "UNKNOWN", "note": err, "exposure": ""})
    return rows


def write_reports(results, rows, prefix):
    meta = {"generated": datetime.now(timezone.utc).isoformat(),
            "cve": "CVE-2026-114938", "projects": len(results)}
    with open(f"{prefix}.json", "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=2)
    fields = ["project", "type", "resource", "location", "detail", "status", "note", "exposure"]
    with open(f"{prefix}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    return f"{prefix}.json", f"{prefix}.csv"


def print_summary(results, rows):
    def count(t, s):
        return sum(1 for r in rows if r["type"] == t and r["status"] == s)

    print("\n" + "═" * 60)
    print(f"Projects scanned: {len(results)}  "
          f"(with errors: {sum(1 for r in results if r['errors'])})")
    print(f"VMs: {sum(len(r['instances']) for r in results)}  "
          f"VBMI-eligible: {count('vm', HW_ELIGIBLE)}  "
          f"not affected: {count('vm', HW_NOT_AFFECTED)}  unknown: {count('vm', HW_UNKNOWN)}")
    ext = [r for r in rows if r["type"] == "vm" and r["status"] == HW_ELIGIBLE and r["exposure"] == "external"]
    if ext:
        print(f"  VBMI-eligible VMs with external IPs: {len(ext)}")
    if any(r["type"] == "container" for r in rows):
        print(f"Containers: CANDIDATE={count('container', 'CANDIDATE')}  "
              f"MITIGATED={count('container', 'MITIGATED')}  "
              f"LIKELY_MITIGATED={count('container', 'LIKELY_MITIGATED')}  "
              f"CANDIDATE_HW_NOT_ELIGIBLE={count('container', 'CANDIDATE_HW_NOT_ELIGIBLE')}  "
              f"UNKNOWN={count('container', 'UNKNOWN')}  "
              f"JAVA_IMAGE_HINT={count('container', 'JAVA_IMAGE_HINT')}")
    autopilot = [c["name"] for r in results for c in r["gke_clusters"] if c["autopilot"]]
    if autopilot:
        print(f"Autopilot clusters (nodes hidden, use --exec-check): {', '.join(autopilot)}")
    print("\nTop findings:")
    priority = {"CANDIDATE": 0, "CANDIDATE_HW_NOT_ELIGIBLE": 1, "JAVA_IMAGE_HINT": 2}
    shown = 0
    for r in sorted((r for r in rows if r["status"] in priority), key=lambda r: priority[r["status"]]):
        print(f"  {r['status']:<26} {r['project']:<28} {r['resource']}")
        shown += 1
        if shown >= 25:
            print("  ... see CSV for the full list")
            break
    if not shown:
        print("  none (this does not clear undiscovered or unprobed runtimes)")
    print("\nHints only: verify vendor backports; hardware results apply to current placement.")


def main():
    global LOG_QUIET
    ap = argparse.ArgumentParser(description="Java4Shell (CVE-2026-114938) GCP estate scanner")
    scope = ap.add_argument_group("scope")
    scope.add_argument("--projects", help="Comma-separated project IDs (default: all visible)")
    scope.add_argument("--org", help="Only projects directly under this organization ID")
    scope.add_argument("--folder", help="Only projects directly under this folder ID")
    scope.add_argument("--filter", help="Extra gcloud projects list filter expression")
    scope.add_argument("--exclude", help="Regex of project IDs to skip")
    depth = ap.add_argument_group("depth")
    depth.add_argument("--k8s", action="store_true", help="List running pods/images in every GKE cluster")
    depth.add_argument("--exec-check", action="store_true",
                       help="Run a read-only probe inside Java-looking containers (implies --k8s)")
    depth.add_argument("--exec-all", action="store_true", help="With --exec-check, probe every container")
    depth.add_argument("--skip-namespaces", default="kube-system,gke-managed-system,gmp-system,"
                       "gke-gmp-system,kube-node-lease,kube-public",
                       help="Namespaces to skip in Kubernetes checks")
    depth.add_argument("--internal-ip", action="store_true",
                       help="Use private endpoints for GKE credentials (run from inside the VPC)")
    depth.add_argument("--network-probe", action="store_true",
                       help="Passive HTTP/TLS/banner probes of the projects' own external IPs")
    depth.add_argument("--ports", default=",".join(map(str, netscan.DEFAULT_PORTS)))
    perf = ap.add_argument_group("performance/output")
    perf.add_argument("--threads", type=int, default=8, help="Projects scanned in parallel")
    perf.add_argument("--exec-threads", type=int, default=10, help="Parallel kubectl exec per cluster")
    perf.add_argument("--timeout", type=int, default=10, help="Per-request timeout seconds")
    perf.add_argument("--out", default=f"java4shell-gcp-{datetime.now():%Y%m%d-%H%M%S}",
                      help="Report file prefix (writes .json and .csv)")
    perf.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    args.skip_namespaces = {n.strip() for n in args.skip_namespaces.split(",") if n.strip()}
    LOG_QUIET = args.quiet

    for tool in ["gcloud"] + (["kubectl"] if (args.k8s or args.exec_check) else []):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found on PATH")

    try:
        projects = list_projects(args)
    except CliError as e:
        sys.exit(f"Could not list projects: {e}")
    if not projects:
        sys.exit("No projects matched.")

    log(f"Java4Shell (CVE-2026-114938) GCP scan: {len(projects)} projects")
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(scan_project, p, args): p["projectId"] for p in projects}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:  # keep going on unexpected per-project failures
                results.append({"project": futs[f], "errors": {"scan": repr(e)}, "instances": [],
                                "gke_clusters": [], "k8s": [], "cloud_run": [],
                                "forwarding_rules": [], "network": []})
    results.sort(key=lambda r: r["project"])

    rows = flatten_findings(results)
    json_path, csv_path = write_reports(results, rows, args.out)
    print_summary(results, rows)
    print(f"\nReports: {json_path}  {csv_path}")
    sys.exit(1 if any(r["status"] == "CANDIDATE" for r in rows) else 0)


if __name__ == "__main__":
    main()
