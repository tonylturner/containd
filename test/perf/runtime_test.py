# SPDX-License-Identifier: Apache-2.0
import http.client
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from runtime import Failure, Runtime


class Ownership(unittest.TestCase):
    def runtime(self, out):
        return Runtime(Path.cwd(), "containd-perf-test", Path(out),
                       {"PERF_APPLIANCE_IMAGE": "test-appliance:owned", "PERF_HELPER_IMAGE": "test-helper:owned"})

    def test_refuses_existing_project_without_cleanup(self):
        with tempfile.TemporaryDirectory() as out:
            rt = self.runtime(out)
            rt.resources = lambda kind: ["existing"] if kind == "container" else []
            with self.assertRaises(Failure):
                rt.assert_unused()
            self.assertFalse(rt.owned)
            rt.compose = lambda *_a, **_kw: self.fail("must not clean an unowned project")
            rt.teardown(Path(out))

    def test_teardown_is_project_scoped_after_failure(self):
        with tempfile.TemporaryDirectory() as out:
            rt = self.runtime(out)
            rt.owned = True
            calls = []
            def run(args, **_kw):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, "", "")
            rt.run = run
            rt.check_oom = lambda: []
            rt.resources = lambda _kind: []
            rt.teardown(Path(out))
            self.assertTrue(all("-p" in c and rt.project in c for c in calls))
            self.assertTrue(any("down" in c and "--volumes" in c for c in calls))
            self.assertEqual(json.loads((Path(out) / "teardown.json").read_text()),
                             dict(container=[], network=[], volume=[]))

    def test_subprocess_failure_propagates(self):
        with tempfile.TemporaryDirectory() as out:
            rt = self.runtime(out)
            with patch("runtime.subprocess.run", return_value=subprocess.CompletedProcess(["false"], 9, "", "bad")):
                with self.assertRaisesRegex(Failure, "command failed \\(9\\)"):
                    rt.run(["false"])

    def test_writes_require_cas(self):
        with tempfile.TemporaryDirectory() as out:
            rt = self.runtime(out)
            with self.assertRaisesRegex(Failure, "acknowledged base"):
                rt.api("/config", {})

    def test_deadline_is_fatal(self):
        with tempfile.TemporaryDirectory() as out:
            rt = self.runtime(out)
            rt.deadline = 0
            with self.assertRaisesRegex(Failure, "wall-time"):
                rt.remaining()

    def test_wall_budget_uses_continuous_clock_when_uptime_pauses(self):
        with tempfile.TemporaryDirectory() as out:
            with patch("runtime.time.monotonic", return_value=10), \
                    patch("runtime.time.clock_gettime", side_effect=[10, 5411]) as clock:
                rt = self.runtime(out)
                with self.assertRaisesRegex(Failure, "wall-time"):
                    rt.remaining()
                clock.assert_called_with(time.CLOCK_MONOTONIC_RAW)


class FailureCleanup(unittest.TestCase):
    def test_failed_load_capture_cleanup_does_not_mask_primary_failure(self):
        from harness import capture_stop
        process = Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        with tempfile.TemporaryDirectory() as out:
            directory = Path(out)
            (directory / "path.pcap").write_bytes(b"")
            capture_stop(Mock(), process, directory, validate=False)
            with self.assertRaisesRegex(ValueError, "empty/header-only"):
                capture_stop(Mock(), process, directory)

    def test_waits_through_initial_management_disconnect(self):
        from harness import wait_http
        rt = Mock()
        rt.api.side_effect = [http.client.RemoteDisconnected("not listening yet"), {}]
        def wait(predicate, _description):
            self.assertFalse(predicate())
            self.assertTrue(predicate())
        rt.wait.side_effect = wait
        wait_http(rt)

    def test_memory_guard_counts_reclaimable_cache(self):
        from harness import check_memory
        check_memory("MemFree: 2097152 kB\nMemAvailable: 4194304 kB\n")
        with self.assertRaisesRegex(Failure, "below 4 GiB .*MemAvailable"):
            check_memory("MemFree: 2097152 kB\nMemAvailable: 4194303 kB\n")

    def test_memory_guard_requires_available_not_free(self):
        from harness import check_memory
        for memory in ("MemFree: 8388608 kB\n", "MemAvailable: invalid kB\n",
                       "MemAvailable: 8388608 MB\n"):
            with self.subTest(memory=memory):
                with self.assertRaisesRegex(Failure, "MemAvailable missing or invalid"):
                    check_memory(memory)

    def test_preflight_failure_always_tears_down(self):
        from harness import trial
        with tempfile.TemporaryDirectory() as out:
            rt = Runtime(Path.cwd(), "containd-perf-test", Path(out), {})
            cleaned = []
            rt.teardown = lambda directory: cleaned.append(directory)
            with patch("harness.setup", side_effect=Failure("VM available memory below 4 GiB")):
                with self.assertRaisesRegex(Failure, "VM available memory"):
                    trial(rt, 0, "modbus", "monitor", False, 1, 100, True, "confirm")
            self.assertEqual(len(cleaned), 1)


if __name__ == "__main__":
    unittest.main()
