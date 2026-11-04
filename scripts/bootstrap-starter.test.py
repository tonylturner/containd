#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline bootstrap prerequisite checks; never starts containers."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


class BootstrapTests(unittest.TestCase):
    def run_bootstrap(self, version="28.1.0", compose=True, engine=True):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        folder = Path(scratch.name)
        docker = folder / "docker"
        docker.write_text("""#!/bin/sh
set -eu
case "$*" in
  'compose version') exit 0 ;;
  'version --format {{.Server.Version}}')
    [ "$TEST_ENGINE" = 1 ] || exit 1
    printf '%s\\n' "$TEST_VERSION"
    ;;
  'compose -p containd-interface-probe -f '*)
    [ "$6" = config ]
    [ "$7" = -q ]
    cp "$5" "$TEST_PROBE"
    [ "$TEST_COMPOSE" = 1 ] || exit 1
    ;;
  'network ls -q') exit 0 ;;
  *) echo "unexpected Docker call: $*" >&2; exit 99 ;;
esac
""")
        docker.chmod(0o755)
        target = folder / "lab"
        probe = folder / "probe.yml"
        env = dict(
            os.environ,
            PATH=f"{folder}:{os.environ['PATH']}",
            TEST_VERSION=version,
            TEST_COMPOSE=str(int(compose)),
            TEST_ENGINE=str(int(engine)),
            TEST_PROBE=str(probe),
        )
        result = subprocess.run(
            ["sh", str(ROOT / "scripts/bootstrap-starter.sh"),
             "--dir", str(target), "--no-start", "--jwt-secret", "a" * 64],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False,
        )
        return result, target, probe

    def test_reject_old_engines_before_creating_lab(self):
        for version in ("27.5.1", "28.0.4"):
            with self.subTest(version=version):
                result, target, probe = self.run_bootstrap(version)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("Docker Engine 28.1+", result.stderr)
                self.assertIn(version, result.stderr)
                self.assertFalse(target.exists())
                self.assertFalse(probe.exists())

    def test_accept_engine_boundary_and_new_major(self):
        for version in ("28.1.0", "29.0.0"):
            with self.subTest(version=version):
                result, target, probe = self.run_bootstrap(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Docker Compose accepts interface_name", result.stdout)
                self.assertIn("interface_name: wan", probe.read_text())
                self.assertIn("interface_name: lan6",
                              (target / "docker-compose.yml").read_text())
                self.assertNotIn("CONTAIND_AUTO_", (target / ".env").read_text())

    def test_reject_unparseable_engine_version(self):
        result, target, _ = self.run_bootstrap("unknown")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Docker Engine 28.1+", result.stderr)
        self.assertFalse(target.exists())

    def test_report_engine_unavailable(self):
        result, target, _ = self.run_bootstrap(engine=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unable to query Docker Engine", result.stderr)
        self.assertFalse(target.exists())

    def test_probe_rejects_compose_without_interface_name(self):
        result, target, probe = self.run_bootstrap(compose=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Compose with interface_name support is required", result.stderr)
        self.assertIn("interface_name: wan", probe.read_text())
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
