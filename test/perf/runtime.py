# SPDX-License-Identifier: Apache-2.0
"""Owned Docker processes, management CAS and bounded measurement telemetry."""
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import urllib.error
import urllib.request


class Failure(RuntimeError):
    pass


def write_json(path, value):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


class Runtime:
    def __init__(self, root, project, out, env, budget=5400):
        self.root, self.project, self.out = root, project, out
        self.env = dict(os.environ, **env, COMPOSE_PROJECT_NAME=project)
        self.deadline = time.monotonic() + budget
        self.owned = False
        self.processes = []
        self.base = None
        self.revision = None

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Failure("harness wall-time budget exceeded")
        return left

    def run(self, args, timeout=120, check=True):
        result = subprocess.run(args, cwd=self.root, env=self.env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=min(timeout, self.remaining()))
        if check and result.returncode:
            raise Failure(f"command failed ({result.returncode}): {args}\n{result.stdout}\n{result.stderr}")
        return result

    def compose_args(self, args):
        return ["docker", "compose", "-p", self.project, "-f", "deploy/docker-compose.perf.yml", *args]

    def compose(self, args, **kw):
        return self.run(self.compose_args(args), **kw)

    def execute(self, service, *args, **kw):
        return self.compose(["exec", "-T", service, *args], **kw)

    def start(self, args, log):
        stream = open(log, "w")
        try:
            p = subprocess.Popen(self.compose_args(args), cwd=self.root, env=self.env,
                                 stdout=stream, stderr=subprocess.STDOUT)
        finally:
            stream.close()
        self.processes.append(p)
        return p

    def resources(self, kind):
        args = ["docker", kind, "ls", "--filter", f"label=com.docker.compose.project={self.project}", "-q"]
        if kind == "container":
            args.insert(3, "-a")
        return self.run(args).stdout.split()

    def assert_unused(self):
        if any(self.resources(kind) for kind in ("container", "network", "volume")):
            raise Failure("project already has resources; refusing ownership or cleanup")
        # Reject pre-existing images at the names we intend to build as well.
        for key in ("PERF_APPLIANCE_IMAGE", "PERF_HELPER_IMAGE"):
            if self.run(["docker", "image", "ls", "-q", self.env[key]]).stdout.strip():
                raise Failure("project image tag already exists; choose a fresh project")

    def api(self, path, body=None):
        headers = {"Authorization": "Bearer devtoken"}
        if body is not None:
            if not self.revision:
                raise Failure("configuration write without acknowledged base revision")
            headers.update({"X-Containd-If-Revision": self.revision, "Content-Type": "application/json"})
        request = urllib.request.Request(self.base + path,
                    data=json.dumps(body).encode() if body is not None else None, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=min(90, self.remaining())) as response:
                data = json.load(response)
                if path == "/config" or body is not None:
                    token = response.headers.get("X-Containd-Revision", "")
                    if not re.fullmatch(r"[0-9a-f]{16}\.[1-9][0-9]*", token):
                        raise Failure("configuration response missing valid revision")
                    self.revision = token
                return data
        except urllib.error.HTTPError as err:
            raise Failure(f"management {path}: HTTP {err.code}: {err.read().decode()}") from err

    def wait(self, predicate, description, seconds=90):
        end = time.monotonic() + min(seconds, self.remaining())
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.25)
        raise Failure(f"timed out waiting for {description}")

    def check_oom(self):
        ids = self.resources("container")
        if not ids:
            raise Failure("owned containers disappeared")
        containers = json.loads(self.run(["docker", "inspect", *ids]).stdout)
        for c in containers:
            if c["State"]["OOMKilled"]:
                raise Failure(f"owned container OOM killed: {c['Name']}")
        return containers

    def teardown(self, directory):
        if not self.owned:
            return
        # Teardown remains permitted after expiry; it must not share the load's
        # expired timeout. Only this explicitly claimed project can be removed.
        original_deadline = self.deadline
        self.deadline = max(self.deadline, time.monotonic() + 120)
        errors = []
        try:
            containers = self.check_oom()
            write_json(directory / "container-final.json", containers)
        except (Failure, subprocess.TimeoutExpired) as err:
            errors.append(str(err))
        logs = self.compose(["logs", "--no-color"], check=False).stdout
        (directory / "compose.log").write_text(logs)
        down = self.compose(["down", "--volumes", "--remove-orphans"], check=False)
        (directory / "down.log").write_text(down.stdout + down.stderr)
        if down.returncode:
            errors.append("owned project teardown failed")
        for p in self.processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.terminate()  # Only our own CLI child, never another process.
                p.wait(timeout=5)
        self.processes.clear()
        evidence = {}
        for kind in ("container", "network", "volume"):
            ids = self.resources(kind)
            evidence[kind] = ids
            if ids:
                errors.append(f"owned {kind} resources remain: {ids}")
        write_json(directory / "teardown.json", evidence)
        self.owned = False
        self.deadline = original_deadline
        if errors:
            raise Failure("; ".join(errors))


def cgroup_sample(text):
    """memory.current/peak, cpu.stat usage_usec, and memory.events oom_kill."""
    data = json.loads(text)
    if data["oom_kill"]:
        raise Failure("cgroup OOM kill observed")
    return data


SAMPLE = r'''printf '{"current":'; cat /sys/fs/cgroup/memory.current
printf ',"peak":'; cat /sys/fs/cgroup/memory.peak
printf ',"usage_usec":'; awk '$1=="usage_usec"{print $2}' /sys/fs/cgroup/cpu.stat
printf ',"oom_kill":'; awk '$1=="oom_kill"{print $2}' /sys/fs/cgroup/memory.events
printf '}\n' '''


class Sampler:
    def __init__(self, runtime, directory):
        self.runtime, self.directory = runtime, directory
        self.stop = threading.Event()
        self.error = None
        self.samples = []
        self.thread = threading.Thread(target=self.loop)

    def sample(self):
        sample = {"at": time.monotonic(), "containers": {}}
        for service in ("appliance", "client", "peer"):
            raw = self.runtime.execute(service, "sh", "-c", SAMPLE, timeout=10).stdout
            sample["containers"][service] = cgroup_sample(raw)
        metrics = self.runtime.execute("appliance", "curl", "-fsS", "--max-time", "5",
                                       "http://127.0.0.1:8081/metrics", timeout=10).stdout
        sample["engine_metrics"] = {p[0]: float(p[1]) for line in metrics.splitlines()
            if len(p := line.split()) == 2 and p[0] in ("go_memstats_heap_alloc_bytes", "process_resident_memory_bytes")}
        if len(sample["engine_metrics"]) != 2:
            raise Failure("engine scrape is missing RSS/Go heap telemetry")
        self.samples.append(sample)
        write_json(self.directory / "resources.json", self.samples)

    def loop(self):
        try:
            while not self.stop.is_set():
                self.runtime.remaining()
                self.runtime.check_oom()
                self.sample()
                self.stop.wait(5)
        except Exception as err:  # Propagated to the coordinator, never ignored.
            self.error = err

    def start(self):
        self.sample()
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=45)
        if self.thread.is_alive():
            raise Failure("telemetry sampler did not stop")
        if self.error:
            raise self.error
        self.sample()
        result = {}
        for name in ("appliance", "client", "peer"):
            pairs = zip(self.samples, self.samples[1:])
            cpu = [(b["containers"][name]["usage_usec"] - a["containers"][name]["usage_usec"]) /
                   ((b["at"] - a["at"]) * 1e6) for a, b in pairs]
            result[name] = {"cpu_cores_peak": max(cpu, default=0),
                            "memory_peak": max(s["containers"][name]["peak"] for s in self.samples)}
        return result
