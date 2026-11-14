#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolated live policy installation, TCP probes and receiver-side evidence."""
import copy
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time

from evidence import check_pcaps, check_verdicts

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(os.environ["DS34_RESULTS"])
LAN, WAN = os.environ["DS34_LAN"], os.environ["DS34_WAN"]
PROJECT = os.environ["COMPOSE_PROJECT_NAME"]
BASE = "http://127.0.0.1:18080/api/v1"
PORTS = {"modbus": 502, "dnp3": 20000, "iec104": 2404}


def compose(*args, **kwargs):
    return subprocess.run(["docker", "compose", "-p", PROJECT, "-f", str(ROOT / "test/ds34/compose.yml"), *args],
                          check=True, **kwargs)


def call(service, *args):
    try:
        return compose("exec", "-T", service, *args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as exc:
        (OUT / "last-command-error.txt").write_bytes(exc.stdout + exc.stderr)
        raise


def save(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2) + "\n")


class API:
    def __init__(self):
        self.revision = None
        self.token = json.loads(call("engine", "curl", "-fsS", "-H", "Content-Type: application/json", "-d",
                                     '{"username":"containd","password":"containd"}', BASE + "/auth/login"))["token"]

    def request(self, path, data=None, method=None):
        args = ["curl", "-fsS", "--fail-with-body", "--max-time", "90", "-D", "-", "-H", "Authorization: Bearer " + self.token]
        if method:
            args += ["-X", method]
        if data is not None or method:
            assert self.revision, "configuration write without revision"
            args += ["-H", "X-Containd-If-Revision: " + self.revision]
        if data is not None:
            args += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
        raw = call("engine", *args, BASE + path).decode()
        head, body = raw.split("\r\n\r\n", 1)
        for line in head.splitlines():
            if line.lower().startswith("x-containd-revision:"):
                self.revision = line.split(":", 1)[1].strip()
        return json.loads(body)

    def install(self, cfg):
        self.request("/config")
        self.request("/config/candidate", cfg)
        result = self.request("/config/commit", method="POST")
        assert result["status"] == "committed", result
        time.sleep(0.2)
        return result


def internal(path):
    return call("engine", "curl", "-fsS", "--max-time", "2", "http://127.0.0.1:8081" + path)


def ready():
    for _ in range(60):
        try:
            call("master", "curl", "-fsS", "--max-time", "2", f"http://{LAN}.2:18080/api/v1/health")
            return
        except subprocess.CalledProcessError:
            time.sleep(1)
    raise AssertionError("management never became ready")


def policy(original, fate="allowed", explicit=True, default="ALLOW"):
    cfg = copy.deepcopy(original)
    cfg["system"]["mgmt"]["httpListenAddr"] = ":18080"
    cfg["system"]["mgmt"]["listenAddr"] = ":18080"
    cfg["zones"] = [{"name": "lan"}, {"name": "wan"}]
    cfg["interfaces"] = [{"name": "lan1", "zone": "lan"},
                         {"name": "wan", "zone": "wan"}]
    cfg["ids"] = {"enabled": True}
    cfg["dataplane"] = {"enforcement": True, "enforceTable": "containd", "nfqueueGroup": 101,
                        "dpiEnabled": True, "dpiMode": "enforce", "dpiMock": False,
                        "dpiIcsProtocols": {p: True for p in PORTS}}
    entries = []
    for proto, port in PORTS.items():
        base = {"id": proto, "action": "ALLOW", "log": True,
                "protocols": [{"name": "tcp", "port": str(port)}],
                "ics": {"protocol": proto, "mode": "enforce"}}
        if fate in ("denied-request", "denied-response"):
            deny = copy.deepcopy(base)
            deny["id"] += "-deny"
            deny["action"] = "DENY"
            deny["ics"]["direction"] = "request" if fate == "denied-request" else "response"
            entries.append(deny)
        if explicit and proto != "modbus":
            for cls in ("autonomous", "session"):
                rule = copy.deepcopy(base)
                rule["id"] += "-" + cls
                rule["ics"]["messageClass"] = cls
                rule["ics"]["direction"] = "response"
                entries.append(rule)
                if cls == "session":
                    request_rule = copy.deepcopy(rule)
                    request_rule["id"] += "-request"
                    request_rule["ics"]["direction"] = "request"
                    entries.append(request_rule)
        entries.append(base)
    cfg["firewall"] = {"defaultAction": default, "rules": entries, "nat": {"enabled": False}}
    return cfg


def capture_start():
    for service in ("master", "outstation", "upstream"):
        call(service, "sh", "-c", f"tcpdump --immediate-mode -U -n -s 0 -i eth0 -w /results/{service}.pcap 'tcp port 502 or tcp port 20000 or tcp port 2404' >/results/{service}-tcpdump.log 2>&1 & echo $! >/tmp/pairing-tcpdump.pid")
    time.sleep(0.3)


def capture_stop():
    for service in ("master", "outstation", "upstream"):
        call(service, "sh", "-c", "kill -INT $(cat /tmp/pairing-tcpdump.pid)")
    time.sleep(0.4)


def operator_check(label, guard=True):
    raw = call("master", "curl", "-fsS", "--max-time", "5", "-H", "Content-Type: application/json", "-d",
               '{"username":"containd","password":"containd"}', f"http://{LAN}.2:18080/api/v1/auth/login")
    token = json.loads(raw)["token"]
    reservation = json.loads(call("master", "curl", "-fsS", "--max-time", "5", "-H", "Authorization: Bearer " + token,
                                 f"http://{LAN}.2:18080/api/v1/system/management-reservation"))
    save(label + "-reservation.json", reservation)
    assert reservation["active"], reservation
    if guard:
        assert reservation["guard"]["active"], reservation


def sample_metrics(stop, samples):
    while not stop.is_set():
        raw = internal("/metrics").decode()
        sample = {"time": time.time()}
        for name in ("held_packets", "held_bytes", "oldest_pending_seconds"):
            match = re.search(r"^containd_dp_iec104_" + name + r" ([^\n]+)", raw, re.MULTILINE)
            assert match, f"missing pressure metric {name}"
            sample[name] = float(match[1])
        samples.append(sample)
        stop.wait(0.1)


def run(mode):
    ready()
    save("manifest.json", {"project": PROJECT, "source": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                           "image": os.environ["DS34_IMAGE"], "peerImage": os.environ["DS34_PEER_IMAGE"],
                           "lan": LAN, "wan": WAN, "nft": call("engine", "nft", "--version").decode().strip()})
    api = API()
    original = api.request("/config")
    save("original.json", original)
    cases, failures = [], []
    capture_start()
    samples, sampling_errors = [], []
    stop = threading.Event()
    def sample():
        try:
            sample_metrics(stop, samples)
        except (subprocess.CalledProcessError, OSError, AssertionError, ValueError) as exc:
            sampling_errors.append(str(exc))
    sampler = threading.Thread(target=sample) if mode == "envelope" else None
    if sampler:
        sampler.start()
    try:
        if mode == "management":
            operator_check("before")
            old = policy(original, explicit=False)
            api.install(old)
            save("legacy-running.json", api.request("/config"))
            operator_check("enforce")
            call("engine", "sh", "-c", "cat /proc/net/netfilter/nfnetlink_queue")
            # Own process only: stopped userspace cannot acknowledge its queue.
            call("engine", "sh", "-c", 'kill -STOP $(pgrep -f "^/usr/bin/containd engine$")')
            try:
                call("master", "curl", "-fsS", "--max-time", "5", f"http://{LAN}.2:18080/api/v1/health")
                operator_check("frozen", guard=False)
            finally:
                call("engine", "sh", "-c", 'kill -CONT $(pgrep -f "^/usr/bin/containd engine$")')
            operator_check("after-outage")
            call("engine", "sh", "-c", 'kill -TERM $(pgrep -f "^/usr/bin/containd engine$")')
            for index in range(5):
                operator_check(f"engine-restart-{index}", guard=False)
                time.sleep(0.3)
            compose("restart", "engine")
            ready()
            for _ in range(30):
                try:
                    internal("/health")
                    break
                except subprocess.CalledProcessError:
                    time.sleep(0.1)
            operator_check("restart")
            running = api.request("/config")
            save("replayed-running.json", running)
            assert running == json.loads((OUT / "legacy-running.json").read_text()), "boot mutated running config"
            status = json.loads(internal("/internal/ruleset_status"))
            save("boot-status.json", status)
            assert status.get("warnings"), "boot replay omitted cutover warnings"
            preview = api.request("/dataplane/ruleset")
            save("boot-preview.json", preview)
            assert preview.get("warnings"), "boot ruleset preview omitted warning"
            preview_rule = api.request("/firewall/rules/preview", old["firewall"]["rules"][0])
            save("boot-rule-preview.json", preview_rule)
            assert preview_rule.get("warnings"), "boot rule preview omitted warning"
            for i in range(8):
                api.install(policy(original, explicit=bool(i % 2)))
                operator_check(f"churn-{i}")
        for proto in PORTS:
            if mode == "delivery":
                variants = [{"fate": f, "expect": "pass" if f == "allowed" else "deny"}
                            for f in ("allowed", "missing", "denied-request", "denied-response")]
            elif mode == "envelope":
                variants = [{"fate": "allowed", "expect": "pass", **opts} for opts in
                            ({"step": 3}, {"step": 1}, {"step": 3, "nodelay": False}, {"slow": True},
                             {"independent": True}, {"step": 3, "delayed_ack": True})]
                variants += [{"fate": "allowed", "expect": "deny", "step": 3, "delay": 1.2, "kind": "timeout"}]
                if proto == "iec104":
                    variants += [{"fate": "allowed", "expect": "pass", "step": 1, "delay": 0, "upstream": True}]
                if proto != "modbus":
                    variants += [{"fate": "missing", "expect": "pass", "kind": "autonomous"}]
                if proto == "dnp3":
                    variants += [{"fate": "allowed", "expect": "pass", "window": True, "kind": "large"},
                                 {"fate": "allowed", "expect": "pass", "window": True, "kind": "large", "monitor": True},
                                 {"fate": "allowed", "expect": "pass", "kind": "confirm"},
                                 {"fate": "allowed", "expect": "deny", "kind": "confirmed-link"}]
            else:
                variants = [{"fate": "missing", "expect": "deny", "explicit": False},
                            {"fate": "allowed", "expect": "pass"}]
                if proto != "modbus":
                    variants += [{"fate": "missing", "expect": "deny", "kind": "autonomous", "explicit": False}]
                if proto == "iec104":
                    variants += [{"fate": "allowed", "expect": "deny", "kind": "session", "explicit": False}]
            if proto == "iec104" and mode != "envelope":
                variants += [{"fate": "allowed", "expect": "pass", "step": 1, "delay": 0, "upstream": True}]
            for variant in variants:
                case = {"id": len(cases), "protocol": proto, "host": WAN + ".10", "port": 42000 + len(cases), **variant}
                cfg = policy(original, case["fate"], explicit=case.get("explicit", True))
                if case.get("monitor"):
                    cfg["dataplane"]["dpiMode"] = "monitor"
                    for rule in cfg["firewall"]["rules"]:
                        rule["ics"]["mode"] = "monitor"
                api.install(cfg)
                if case.get("upstream"):
                    case["host"] = WAN + ".11"
                save("case.json", case)
                cases.append(case)
                save("cases.json", cases)
                try:
                    result = call("master", "python3", "/fixtures/ds34/peers/tcp/peer.py", "client", json.dumps(case))
                    (OUT / f"case-{case['id']}.log").write_bytes(result)
                except subprocess.CalledProcessError as exc:
                    (OUT / f"case-{case['id']}.log").write_bytes(exc.stdout + exc.stderr)
                    failures.append(f"case {case['id']}: {proto} {variant}: peer assertion failed")
                time.sleep(0.2)
        time.sleep(1.3)
        peer_log = compose("logs", "--no-color", "outstation", stdout=subprocess.PIPE).stdout
        (OUT / "peer.log").write_bytes(peer_log)
        for case in cases:
            if case.get("kind") == "confirm" and not any('"event": "confirm"' in line and str(case["port"]) in line for line in peer_log.decode().splitlines()):
                failures.append(f"case {case['id']}: outstation never received application Confirm")
        limits = json.loads(internal("/internal/diagnostics/state-limits"))
        save("state-limits.json", limits)
        assert 0 < limits["budget"]["highWater"] <= limits["budget"]["limit"], limits
        (OUT / "metrics.txt").write_bytes(internal("/metrics"))
        (OUT / "ruleset.json").write_bytes(internal("/internal/ruleset_status"))
    finally:
        stop.set()
        if sampler:
            sampler.join()
        save("pressure-samples.json", samples)
        if mode == "envelope":
            failures += sampling_errors
            if not samples or max(row["held_packets"] for row in samples) == 0:
                failures.append("no live held-token high-water observed")
            if samples and max(row["held_packets"] for row in samples) > 256:
                failures.append("global held-token ceiling exceeded")
            save("pressure-high-water.json", {key: max((row[key] for row in samples), default=0) for key in ("held_packets", "held_bytes", "oldest_pending_seconds")})
        capture_stop()
    failures += check_pcaps(OUT, cases)
    failures += check_verdicts(OUT)
    save("result.json", {"mode": mode, "cases": len(cases), "failures": failures})
    for failure in failures:
        print("FAIL:", failure)
    assert not failures, f"{len(failures)} failed assertions; evidence in {OUT}"
    print(f"PASS: {mode}, {len(cases)} TCP cases; evidence in {OUT}")


if __name__ == "__main__":
    run(sys.argv[1])
