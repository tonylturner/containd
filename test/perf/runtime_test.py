# SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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


class FailureCleanup(unittest.TestCase):
    def test_preflight_failure_always_tears_down(self):
        from harness import trial
        with tempfile.TemporaryDirectory() as out:
            rt = Runtime(Path.cwd(), "containd-perf-test", Path(out), {})
            cleaned = []
            rt.teardown = lambda directory: cleaned.append(directory)
            with patch("harness.setup", side_effect=Failure("VM free memory below 4 GiB")):
                with self.assertRaisesRegex(Failure, "VM free memory"):
                    trial(rt, 0, "modbus", "monitor", False, 1, 100, True, "confirm")
            self.assertEqual(len(cleaned), 1)


if __name__ == "__main__":
    unittest.main()
