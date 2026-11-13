# SPDX-License-Identifier: Apache-2.0
"""Reproduce routed inline ICS figures without changing product capture paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import urllib.error

from results import (choose_subnets, delta, hits, network_stats, pcap_summary,
                     project_name, protocol_stats, queue_delta, queue_stats,
                     summarize, tables, verify_smoke)
from runtime import Failure, Runtime, Sampler, elapsed, write_json

PORTS = {"modbus": 502, "dnp3": 20000, "iec104": 2404}
ROOT = Path(__file__).resolve().parents[2]


def redact(value):
    if isinstance(value, dict):
        return {k: ("REDACTED" if any(s in k.lower() for s in
                    ("password", "secret", "token", "privatekey")) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def config_for(base, protocol, mode, dpi, lan, wan):
    if mode == "enforce" and not dpi:
        raise Failure("enforce with DPI off is not a measurement")
    rule = dict(id="perf-inspection", sourceZones=["lan"], destZones=["wan"],
                sources=[lan + "/32"], destinations=[wan + "/32"],
                protocols=[dict(name="tcp", port=str(PORTS[protocol]))], action="ALLOW",
                ics=dict(protocol=protocol, mode=mode))
    if mode == "enforce":
        if protocol == "modbus":
            rule["ics"].update(functionCode=[3], readOnly=True)
        elif protocol == "dnp3":
            rule["ics"].update(functionCode=[1, 129], readOnly=True)
        else:
            # Safe-read includes STARTDT and S acknowledgements: these have
            # neither an ASDU type nor a common address to match.
            rule["ics"].update(readOnly=True)
    rules = [rule]
    if mode == "monitor":
        rules.append({k: v for k, v in dict(rule, id="perf-l4").items() if k != "ics"})
    system = json.loads(json.dumps(base["system"]))
    system.setdefault("mgmt", {}).update(httpListenAddr=":18080", listenAddr=":18080")
    return dict(schema_version=base["schema_version"], system=system,
                zones=[dict(name="lan"), dict(name="wan")],
                interfaces=[dict(name="lan1", zone="lan"), dict(name="wan", zone="wan")],
                dataplane=dict(enforcement=True, enforceTable="containd", nfqueueGroup=101,
                               dpiEnabled=dpi, dpiMode=mode, dpiMock=False, dpiExclusions=[],
                               dpiIcsProtocols={p: True for p in PORTS}),
                ids=dict(enabled=False), firewall=dict(defaultAction="DENY", rules=rules,
                                                        nat=dict(enabled=False)))


def configure(rt, protocol, mode, dpi, directory):
    config = config_for(rt.api("/config"), protocol, mode, dpi,
                        rt.env["PERF_LAN_CLIENT"], rt.env["PERF_WAN_PEER"])
    rt.api("/config", config)
    committed = rt.api("/config/commit", {})
    if committed.get("status") != "committed" or not committed.get("runningRevision") or not committed.get("applyId"):
        raise Failure(f"config commit not applied: {committed}")
    write_json(directory / "applied-config.json", redact(config))
    write_json(directory / "commit.json", committed)
    write_json(directory / "config-revision.json", rt.revision)


def ready(rt, protocol, mode, dpi):
    state = rt.api("/dataplane/ruleset/status")
    if state.get("error") or not state.get("installed"):
        return False
    # Monitor with the master switch off is explicitly not inspected; do not
    # pretend static coverage can certify runtime decoding.
    if dpi:
        expected = "enforcing" if mode == "enforce" else "monitoring"
        if not any(r["ruleId"] == "perf-inspection" and r["state"] == expected
                   for r in state.get("icsCoverage", [])):
            return False
    protection = rt.api("/dataplane/protection")
    if protection.get("state") not in ("protecting", "monitoring"):
        return False
    queue_stats(rt.execute("appliance", "cat", "/proc/net/netfilter/nfnetlink_queue").stdout)
    return True


def connect(rt, service, host, port, expected=True):
    result = rt.execute(service, "/usr/local/bin/perf", "-mode", "connect", "-addr", f"{host}:{port}",
                        "-timeout", "750ms", check=False, timeout=10)
    if (result.returncode == 0) != expected:
        raise Failure(f"{'allowed' if expected else 'denied'} control probe failed: {result.stdout}{result.stderr}")
    return dict(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)


def wait_http(rt):
    def available():
        try:
            rt.api("/health")
            return True
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            return False
    rt.wait(available, "management API")


def check_memory(memory):
    fields = dict(line.split(":", 1) for line in memory.splitlines() if ":" in line)
    value = fields.get("MemAvailable", "").split()
    if len(value) != 2 or value[1] != "kB" or not value[0].isdigit():
        raise Failure("VM MemAvailable missing or invalid in /proc/meminfo")
    available = int(value[0]) * 1024
    if available < 4 * 2**30:
        raise Failure(f"VM available memory below 4 GiB ({available} bytes MemAvailable)")


def setup(rt, directory, protocol, mode, dpi):
    rt.env["PERF_RESULTS"] = str(directory)
    rt.owned = True  # Claimed before creation, including a partially failed up.
    rt.compose(["up", "-d", "client"])
    memory = rt.execute("client", "cat", "/proc/meminfo").stdout
    (directory / "guest-meminfo-preflight.txt").write_text(memory)
    check_memory(memory)
    rt.compose(["up", "-d"])
    address = rt.compose(["port", "appliance", "18080"]).stdout.strip()
    host, port = address.rsplit(":", 1)
    if host != "127.0.0.1" or int(port) in (8080, 8443, 2222, 9080, 9443):
        raise Failure(f"unexpected management binding: {address}")
    rt.base = f"http://{address}/api/v1"
    wait_http(rt)
    # Both endpoint default routes must traverse the appliance, not Docker's
    # bridge gateway. There is no shared endpoint network or NAT.
    for service, gateway, destination in (("client", rt.env["PERF_LAN_ENGINE"], rt.env["PERF_WAN_PEER"]),
                                           ("peer", rt.env["PERF_WAN_ENGINE"], rt.env["PERF_LAN_CLIENT"])):
        rt.execute(service, "ip", "route", "replace", "default", "via", gateway)
        route = rt.execute(service, "ip", "-j", "route", "get", destination).stdout
        if json.loads(route)[0].get("gateway") != gateway:
            raise Failure("endpoint route does not traverse appliance")
        (directory / f"{service}-route.json").write_text(route)
        offloads = rt.execute(service, "ethtool", "-k", "eth0").stdout
        (directory / f"{service}-offloads.txt").write_text(offloads)
        # Record observed IP skb rates, not physical packet rates. Offloads
        # remain untouched and their effects stay visible in the manifest.
        info = rt.execute(service, "sh", "-c",
            "uname -a; cat /proc/cpuinfo; cat /proc/meminfo; ip -j link; "
            "cat /proc/sys/net/ipv4/ip_local_port_range; ulimit -n; apk info -v").stdout
        (directory / f"{service}-environment.txt").write_text(info)
    interfaces = rt.api("/interfaces/state")
    for name, ip in (("lan1", rt.env["PERF_LAN_ENGINE"]), ("wan", rt.env["PERF_WAN_ENGINE"])):
        if not any(row["name"] == name and any(a.split("/")[0] == ip for a in row.get("addrs", []))
                   for row in interfaces):
            raise Failure(f"interface binding missing: {name}/{ip}")
    write_json(directory / "interfaces.json", interfaces)
    configure(rt, protocol, mode, dpi, directory)
    rt.wait(lambda: ready(rt, protocol, mode, dpi), "applied rules, protection and bound queue")
    rt.wait(lambda: (directory / "peer.json").exists(), "peer listeners")
    # A listener must be live before denial is evidence of filtering.
    positive = connect(rt, "peer", "127.0.0.1", 25000)
    denied = connect(rt, "client", rt.env["PERF_WAN_PEER"], 25000, expected=False)
    write_json(directory / "denied-control.json", dict(listener=positive, denied=denied))
    write_json(directory / "allowed-control.json",
               connect(rt, "client", rt.env["PERF_WAN_PEER"], PORTS[protocol]))
    # Appliance down is an outage preflight, not a dataplane performance row.
    rt.compose(["stop", "-t", "10", "appliance"])
    down_probe = connect(rt, "client", rt.env["PERF_WAN_PEER"], PORTS[protocol], expected=False)
    rt.compose(["start", "appliance"])
    # Docker may allocate a different ephemeral host port on container restart.
    address = rt.compose(["port", "appliance", "18080"]).stdout.strip()
    host, port = address.rsplit(":", 1)
    if host != "127.0.0.1" or int(port) in (8080, 8443, 2222, 9080, 9443):
        raise Failure(f"unexpected restarted management binding: {address}")
    rt.base = f"http://{address}/api/v1"
    wait_http(rt)
    rt.wait(lambda: ready(rt, protocol, mode, dpi), "replayed policy after outage")
    write_json(directory / "appliance-down-control.json", down_probe)
    rt.check_oom()
    write_json(directory / "helper-version.json", json.loads(rt.execute("peer", "/usr/local/bin/perf", "-mode", "version").stdout))
    (directory / "appliance-tools.txt").write_text(rt.execute("appliance", "sh", "-c", "nft --version; ip -V; curl --version; uname -a; cat /proc/sys/net/netfilter/nf_conntrack_max").stdout)
    rendered = rt.compose(["config"]).stdout
    (directory / "compose.yml").write_text(rendered)


def snapshot(rt, directory, prefix):
    value = {"protocols": rt.api("/stats/protocols"),
             "limits": rt.api("/diagnostics/state-limits"),
             "protection": rt.api("/dataplane/protection"),
             "coverage": rt.api("/dataplane/ics-coverage"),
             "queue": queue_stats(rt.execute("appliance", "cat", "/proc/net/netfilter/nfnetlink_queue").stdout),
             "peer_network": network_stats(rt.execute("peer", "nstat", "-az").stdout),
             "client_network": network_stats(rt.execute("client", "nstat", "-az").stdout),
             "peer": json.loads((directory / "peer.json").read_text()),
             "conntrack": rt.api("/conntrack?limit=4096")}
    (directory / f"{prefix}-nft.json").write_text(rt.execute("appliance", "nft", "-j", "list", "ruleset").stdout)
    (directory / f"{prefix}-ss.txt").write_text(rt.execute("peer", "ss", "-Htn", "state", "established").stdout)
    write_json(directory / f"{prefix}.json", value)
    return value


def capture_start(rt, directory):
    return rt.start(["exec", "-T", "peer", "sh", "-c",
        "tcpdump --immediate-mode -U -n -i eth0 -c 128 -s 128 -w /results/path.pcap 'ip' & "
        "pid=$!; echo $pid > /results/capture.pid; wait $pid"], directory / "capture.log")


def capture_stop(rt, process, directory, validate=True):
    if process.poll() is None:
        pid = (directory / "capture.pid").read_text().strip()
        if not pid.isdigit():
            raise Failure("invalid owned capture PID")
        rt.execute("peer", "sh", "-c",
                   f'if [ "$(cat /proc/{pid}/comm 2>/dev/null)" = tcpdump ]; then kill -INT {pid}; fi')
    code = process.wait(timeout=10)
    if code:
        raise Failure(f"path capture failed ({code})")
    if not validate:
        return  # A failed load has no path sample to validate; retain its evidence.
    result = pcap_summary((directory / "path.pcap").read_bytes())
    # tcpdump's stderr includes capture/kernel drops; require the terminal report.
    log = (directory / "capture.log").read_text()
    if "packets dropped by kernel" not in log:
        raise Failure("path capture missing loss report")
    result["tcpdump_report"] = log
    write_json(directory / "path.json", result)


def trial(rt, index, protocol, mode, dpi, sessions, rate, smoke, stage):
    directory = rt.out / "trials" / f"{index:03}-{protocol}-{mode}-{'on' if dpi else 'off'}"
    directory.mkdir(parents=True)
    sampler, capture = None, None
    try:
        print(f"{directory.name}: {stage}, N={sessions}, offered={rate} tx/s", flush=True)
        setup(rt, directory, protocol, mode, dpi)
        # Same-side control uses the same protocol implementation and rate. It
        # is calibration, never substituted for the routed measurement.
        calibration = directory / "calibration"
        calibration.mkdir()
        (calibration / "go").touch()
        (calibration / "release").touch()
        rt.execute("peer", "/usr/local/bin/perf", "-protocol", protocol, "-addr", f"127.0.0.1:{PORTS[protocol]}",
                   "-sessions", str(sessions), "-rate", str(rate), "-warmup", "0s", "-measure", "2s",
                   "-dir", "/results/calibration", timeout=60)
        rt.wait(lambda: json.loads((directory / "peer.json").read_text())["established"] == 0,
                "calibration sockets closed")
        capture = capture_start(rt, directory)
        load = rt.start(["exec", "-T", "client", "/usr/local/bin/perf", "-protocol", protocol,
                         "-addr", f"{rt.env['PERF_WAN_PEER']}:{PORTS[protocol]}", "-sessions", str(sessions),
                         "-rate", str(rate), "-warmup", "1s" if smoke else "10s",
                         "-measure", "3s" if smoke else "60s"], directory / "load.log")
        def application_ready():
            if load.poll() is not None:
                raise Failure(f"load exited before application readiness: {(directory / 'load.log').read_text()}")
            rt.check_oom()
            return (directory / "ready.json").exists()
        rt.wait(application_ready, "application-ready load sockets", seconds=60)
        rt.wait(lambda: json.loads((directory / "peer.json").read_text())["ready"] == sessions + 1,
                "peer application-ready socket count")
        before = snapshot(rt, directory, "before")
        if before["peer"]["established"] != sessions + 1 or before["peer"]["ready"] != sessions + 1:
            raise Failure("server/client ready session counts disagree")
        capture_stop(rt, capture, directory)
        capture = None
        sampler = Sampler(rt, directory)
        sampler.start()
        (directory / "go").touch()
        def finished():
            if sampler.error:
                raise sampler.error
            if load.poll() is not None:
                raise Failure("load exited before result; inspect load.log")
            return (directory / "result.json").exists()
        rt.wait(finished, "steady result", seconds=90)
        after = snapshot(rt, directory, "after")
        resources = sampler.finish()
        sampler = None
        result = json.loads((directory / "result.json").read_text())
        (directory / "release").touch()
        code = load.wait(timeout=10)
        expected_code = 0 if result["main"]["errors"] + result["probe"]["errors"] == 0 else 1
        if code != expected_code:
            raise Failure(f"load exit/result disagreement ({code})")
        pd = delta(protocol_stats(before["protocols"], protocol), protocol_stats(after["protocols"], protocol))
        qd = queue_delta(before["queue"], after["queue"])
        successful = result["main"]["success"] + result["probe"]["success"]
        if qd["received"] <= 0 or pd["packetCount"] <= 0:
            raise Failure("measured workload did not traverse NFQUEUE")
        if (dpi and pd["eventCount"] < successful) or (not dpi and pd["eventCount"] != 0):
            raise Failure(f"decode proof failed: DPI={dpi}, event delta={pd['eventCount']}, successes={successful}")
        if any(after["protection"][key] != before["protection"][key]
               for key in ("state", "bootId", "applyId", "runningRevision")):
            raise Failure("protection changed during measurement")
        cap_hits = hits(after["limits"]) - hits(before["limits"])
        if cap_hits < 0:
            raise Failure("cap ledger reset")
        row = dict(protocol=protocol, mode=mode, dpi=dpi, sessions=sessions, rate=rate, stage=stage,
                   directory=str(directory.relative_to(rt.out)), load=result, resources=resources,
                   protocol_delta=pd, queue_delta=qd, cap_hits=cap_hits,
                   peer_network_delta=delta(before["peer_network"], after["peer_network"]),
                   client_network_delta=delta(before["client_network"], after["client_network"]))
        row["summary"] = summarize(row)
        if after["peer"]["ready"] != sessions + 1 or after["peer"]["established"] != sessions + 1:
            row["summary"]["sustainable"] = False
        row["endpoint_limited"] = (resources["peer"]["cpu_cores_peak"] >= 1.8 or
                                    resources["client"]["cpu_cores_peak"] >= 1.8)
        write_json(directory / "row.json", row)
        if smoke:
            verify_smoke(row)
        print(f"  queue +{qd['received']}; eventCount +{pd['eventCount']}; successes {successful}; denied control verified", flush=True)
        return row
    finally:
        try:
            if sampler is not None:
                sampler.finish()
            if capture is not None:
                capture_stop(rt, capture, directory, validate=False)
        finally:
            rt.teardown(directory)


def manifest(rt, smoke):
    info = json.loads(rt.run(["docker", "info", "--format", "{{json .}}"], timeout=30).stdout)
    settings = json.loads(os.environ.get("PERF_DESKTOP_SETTINGS_JSON", "null"))
    if not smoke and (not isinstance(settings, dict) or not all(k in settings for k in
                    ("version", "backend", "network", "cpus", "memory_gib", "swap_gib"))):
        raise Failure("full profile requires PERF_DESKTOP_SETTINGS_JSON; see performance documentation")
    sha = rt.run(["git", "rev-parse", "HEAD"]).stdout.strip()
    status = rt.run(["git", "status", "--porcelain=v1"]).stdout
    patch = rt.run(["git", "diff", "HEAD", "--", "scripts/perf-dataplane.sh", "scripts/perf-dataplane.test.sh",
                    "deploy/docker-compose.perf.yml", "test/perf", "docs/mkdocs/performance.md", "CHANGELOG.md"]).stdout
    hardware = rt.run(["system_profiler", "SPHardwareDataType", "-json"], timeout=30).stdout
    hardware = json.loads(hardware)
    hardware = [{k: v for k, v in item.items() if not any(s in k.lower() for s in ("serial", "uuid", "udid"))}
                for item in hardware["SPHardwareDataType"]]
    value = dict(schema=1, label="Docker Desktop lab measurements", publishable=False,
                 profile="smoke" if smoke else "full", source_sha=sha, source_status=status,
                 owned_patch_sha256=hashlib.sha256(patch.encode()).hexdigest(), version=(ROOT / "VERSION").read_text().strip(),
                 timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), seed=20261113,
                 host=dict(hardware=hardware, python=platform.python_version(),
                           macos=rt.run(["sw_vers"]).stdout, power=rt.run(["pmset", "-g", "custom"]).stdout),
                 docker={k: info.get(k) for k in ("NCPU", "MemTotal", "KernelVersion", "OperatingSystem", "Architecture", "ServerVersion", "ContainersRunning")},
                 desktop_declared=settings, docker_version=json.loads(rt.run(["docker", "version", "--format", "{{json .}}"]).stdout or "null"),
                 compose_version=rt.run(["docker", "compose", "version"]).stdout,
                 build_flags="CGO_ENABLED=0 GOOS=linux GOARCH=arm64 -trimpath; product Dockerfile defaults",
                 limits=dict(appliance=dict(cpus=4, memory=2 * 2**30), endpoints=dict(cpus=2, memory=512 * 2**20)),
                 ceiling_seconds=5400, budget_clock="Darwin CLOCK_MONOTONIC_RAW",
                 min_available_bytes=4 * 2**30,
                 workload=dict(ip="IPv4", mtu=1500, nat=False, tcp_nodelay=True, outstanding_per_session=1,
                               probe_tps=10, histogram="1% logarithmic upper bounds, microseconds, 1802 bins",
                               omission="paced closed loop; late slots counted, never caught up",
                               semantics=dict(modbus="FC3 registers 0..1", dnp3="class-0 read, solicited binary input",
                                              iec104="STARTDT; C_RD_NA_1 IOA1, M_SP_NA_1 COT5, S ack")))
    # Retain authored helper bytes too: git diff does not include untracked files.
    value["harness_files"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in (ROOT / "test/perf").iterdir() if p.is_file()}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke", action="store_true", help="short plumbing check; never publish")
    args = parser.parse_args()
    name = project_name(os.environ.get("COMPOSE_PROJECT_NAME", ""))
    out = ROOT / "build/perf" / name
    if out.exists():
        raise Failure("result directory already exists; choose a fresh unique project")
    out.mkdir(parents=True)
    os.chmod(out, 0o700)
    env = {"PERF_APPLIANCE_IMAGE": f"containd-perf-appliance:{name}",
           "PERF_HELPER_IMAGE": f"containd-perf-helper:{name}", "PERF_RESULTS": str(out)}
    rt = Runtime(ROOT, name, out, env, budget=5190)  # Reserve 210 seconds for stack and image teardown.
    built_images = []
    rows, bundle = [], {"schema": 1, "status": "incomplete", "rows": []}
    def interrupted(signum, _frame):
        raise Failure(f"interrupted by signal {signum}")
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        rt.assert_unused()
        bundle["manifest"] = manifest(rt, args.smoke)
        ids = rt.run(["docker", "network", "ls", "-q"]).stdout.split()
        networks = json.loads(rt.run(["docker", "network", "inspect", *ids]).stdout) if ids else []
        existing = [c["Subnet"] for n in networks for c in (n["IPAM"].get("Config") or []) if c.get("Subnet")]
        lan, wan = choose_subnets(existing, 20261113)
        rt.env.update(PERF_LAN_SUBNET=str(lan), PERF_WAN_SUBNET=str(wan),
                      PERF_LAN_ENGINE=str(lan[2]), PERF_LAN_CLIENT=str(lan[3]),
                      PERF_WAN_ENGINE=str(wan[2]), PERF_WAN_PEER=str(wan[3]))
        rt.compose(["config", "--quiet"])
        print(f"Building native arm64 images for {name}", flush=True)
        for dockerfile, tag in (("test/perf/Dockerfile", env["PERF_HELPER_IMAGE"]),
                                ("build/Dockerfile.mgmt", env["PERF_APPLIANCE_IMAGE"])):
            result = rt.run(["docker", "build", "--platform", "linux/arm64", "--build-arg",
                             "COMMIT=" + bundle["manifest"]["source_sha"], "-f", dockerfile, "-t", tag, "test/perf" if "test/" in dockerfile else "."], timeout=1800)
            built_images.append(tag)
            (out / ("build-helper.log" if "test/" in dockerfile else "build-product.log")).write_text(result.stdout + result.stderr)
        images = json.loads(rt.run(["docker", "image", "inspect", env["PERF_HELPER_IMAGE"], env["PERF_APPLIANCE_IMAGE"]]).stdout)
        if any(i["Architecture"] != "arm64" or i["Os"] != "linux" for i in images):
            raise Failure("native linux/arm64 images required")
        bundle["manifest"]["images"] = images
        def measure(protocol, mode, dpi, sessions, rate, stage):
            row = trial(rt, len(rows), protocol, mode, dpi, sessions, rate, args.smoke, stage)
            rows.append(row)
            bundle["rows"] = rows
            write_json(out / "bundle.json", bundle)
            (out / "figures.md").write_text(tables(rows, args.smoke))
            return row
        for protocol in PORTS:
            sessions, rate = 1, 100
            if not args.smoke:
                # Exploratory observations do not become replicated headline
                # rows. Confirm one matched point five times within the budget.
                highest, failing = 0, None
                for candidate, offered in ((1, 100), (8, 1000), (32, 1000)):
                    row = measure(protocol, "monitor", True, candidate, offered, "explore")
                    if row["summary"]["sustainable"] and not row["endpoint_limited"]:
                        highest, sessions, rate = candidate, candidate, offered
                    else:
                        failing = candidate
                        break
                if not highest:
                    raise Failure("no sustainable baseline; inspect first exploratory trial")
                if failing and failing - highest > 1:
                    candidate = (failing + highest) // 2
                    row = measure(protocol, "monitor", True, candidate, 1000, "explore")
                    if row["summary"]["sustainable"] and not row["endpoint_limited"]:
                        sessions, rate = candidate, 1000
            for repetition in range(1 if args.smoke else 5):
                pair = [False, True] if repetition % 2 == 0 else [True, False]
                for dpi in pair:
                    measure(protocol, "monitor", dpi, sessions, rate, "confirm")
                measure(protocol, "enforce", True, sessions, rate, "confirm")
        bundle["status"] = "complete"
        bundle["manifest"]["publishable"] = not args.smoke
    except Exception as err:
        bundle["failure"] = str(err)
        raise
    finally:
        # Image tags, unlike shared build-cache layers, belong to this run too.
        # Keep teardown possible after the workload deadline; never prune.
        rt.deadline = max(rt.deadline, elapsed() + 90)
        cleanup_errors = []
        for tag in built_images:
            result = rt.run(["docker", "image", "rm", tag], check=False, timeout=30)
            if result.returncode:
                cleanup_errors.append(result.stderr)
        if cleanup_errors:
            bundle["status"] = "incomplete"
            bundle["cleanup_failure"] = cleanup_errors
            if "manifest" in bundle:
                bundle["manifest"]["publishable"] = False
        bundle["rows"] = rows
        write_json(out / "bundle.json", bundle)
        (out / "figures.md").write_text(tables(rows, args.smoke))
        print(f"Evidence: {out}", flush=True)
        if cleanup_errors:
            raise Failure("owned image cleanup failed; see bundle.json")
    print("Completed; all owned containers, networks and volumes removed.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (Failure, ValueError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"performance harness: {exc}", file=sys.stderr)
        sys.exit(1)
