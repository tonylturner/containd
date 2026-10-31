#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline tests, including the release workflow's actual polling run block."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/release-ci-gate.py"
spec = importlib.util.spec_from_file_location("release_ci_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
# Do not leave __pycache__ in the source tree.
sys.dont_write_bytecode = True
spec.loader.exec_module(gate)
SHA = "a" * 40
REPO = "example/containd"
RUN = {
    "id": 123,
    "run_number": 10,
    "run_attempt": 1,
    "head_sha": SHA,
    "event": "push",
    "head_branch": "main",
    "name": "CI",
    "path": ".github/workflows/ci.yml@main",
    "status": "completed",
    "conclusion": "success",
}


def pages(*runs):
    return [{"workflow_runs": list(runs)}]


def pending(**changes):
    return dict(RUN, status="in_progress", conclusion=None, **changes)


class DecisionTests(unittest.TestCase):
    def decide(self, data, final=False):
        return gate.decide(data, SHA, REPO, final)

    def test_exact_success_and_evidence(self):
        code, summary = self.decide(pages(RUN))
        self.assertEqual(code, 0)
        for expected in (SHA, "[123](https://github.com/example/containd/actions/runs/123)",
                         "attempt 1", "`success`", "**PASSED:**"):
            self.assertIn(expected, summary)

    def test_unrelated_success_never_counts(self):
        for change in (
            {"event": "pull_request"},
            {"head_sha": "b" * 40},
            {"head_branch": "feature"},
            {"name": "Other workflow"},
        ):
            with self.subTest(change=change):
                code, summary = self.decide(pages(dict(RUN, **change)))
                self.assertEqual(code, 1)
                self.assertIn("No CI run", summary)

    def test_non_success_conclusions_refuse(self):
        for conclusion in ("failure", "cancelled", "timed_out", "neutral", "skipped",
                           "action_required", "stale", None):
            with self.subTest(conclusion=conclusion):
                code, summary = self.decide(pages(dict(RUN, conclusion=conclusion)))
                self.assertEqual(code, 1)
                self.assertIn("**REFUSED:**", summary)

    def test_all_pending_states_wait_then_refuse(self):
        for status in gate.PENDING:
            with self.subTest(status=status):
                data = pages(dict(RUN, status=status, conclusion=None))
                self.assertEqual(self.decide(data)[0], 3)
                code, summary = self.decide(data, final=True)
                self.assertEqual(code, 1)
                self.assertIn("Timed out", summary)
                self.assertIn("workflow_dispatch", summary)

    def test_missing_run_refuses_immediately(self):
        self.assertEqual(self.decide(pages())[0], 1)

    def test_latest_attempt_wins_in_either_order_and_across_pages(self):
        for old, new, expected in (
            ("failure", "success", 0),
            ("success", "failure", 1),
            ("success", "cancelled", 1),
        ):
            first = dict(RUN, conclusion=old)
            latest = dict(RUN, run_attempt=2, conclusion=new)
            for runs in ([first, latest], [latest, first]):
                with self.subTest(old=old, new=new, order=runs):
                    code, summary = self.decide(
                        [{"workflow_runs": [r]} for r in runs]
                    )
                    self.assertEqual(code, expected)
                    self.assertIn("attempt 2", summary)

    def test_latest_pending_attempt_does_not_reuse_old_success(self):
        self.assertEqual(self.decide(pages(RUN, pending(run_attempt=2)))[0], 3)

    def test_newest_run_supersedes_old_green_run(self):
        newer = dict(RUN, id=124, run_number=11, conclusion="failure")
        old = dict(RUN, run_attempt=5)
        code, summary = self.decide(pages(newer, old))
        self.assertEqual(code, 1)
        self.assertIn("[124]", summary)

    def test_unknown_status_refuses(self):
        self.assertEqual(self.decide(pages(dict(RUN, status="unknown")))[0], 1)


def polling_block():
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    step = workflow.split(
        "      - name: Require successful CI for the exact release commit\n", 1
    )[1].split("\n      - uses:", 1)[0]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


class WorkflowTests(unittest.TestCase):
    def run_poll(self, snapshots, api_failure=False):
        with tempfile.TemporaryDirectory(prefix="containd-ci-gate-") as directory:
            temp = Path(directory)
            bin_dir = temp / "bin"
            bin_dir.mkdir()
            (temp / "snapshots.json").write_text(json.dumps(snapshots))
            # Never call the real gh, timeout or sleep, even on a developer host.
            programs = {
                "gh": f"""#!{sys.executable}
import json, os, pathlib, sys
p = pathlib.Path(os.environ["RUNNER_TEMP"])
n = int((p / "calls").read_text()) if (p / "calls").exists() else 0
(p / "calls").write_text(str(n + 1))
with (p / "args").open("a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
if os.environ["FAKE_API_FAILURE"] == "1":
    sys.exit(1)
snapshots = json.loads((p / "snapshots.json").read_text())
print(json.dumps(snapshots[min(n, len(snapshots) - 1)]))
""",
                "sleep": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$RUNNER_TEMP/sleeps\"\n",
                "timeout": "#!/bin/sh\nshift\nexec \"$@\"\n",
            }
            for name, program in programs.items():
                path = bin_dir / name
                path.write_text(program)
                path.chmod(0o755)
            summary_path = temp / "summary"
            result = subprocess.run(
                ["bash"], input=polling_block(), text=True, capture_output=True,
                cwd=ROOT, env={
                    **os.environ,
                    "PATH": f"{bin_dir}:{os.environ['PATH']}",
                    "RUNNER_TEMP": str(temp),
                    "GITHUB_STEP_SUMMARY": str(summary_path),
                    "GITHUB_REPOSITORY": REPO,
                    "RELEASE_COMMIT": SHA,
                    "FAKE_API_FAILURE": str(int(api_failure)),
                },
                timeout=30,
            )
            self.assertTrue(
                summary_path.exists(),
                f"Missing CI summary (exit {result.returncode}): {result.stderr}",
            )
            calls = int((temp / "calls").read_text())
            sleeps = (temp / "sleeps").read_text().splitlines() if (
                temp / "sleeps"
            ).exists() else []
            args = [json.loads(line) for line in (temp / "args").read_text().splitlines()]
            for call in args:
                self.assertEqual(call[:3], ["api", "--paginate", "--slurp"])
                self.assertEqual(
                    call[3], f"repos/{REPO}/actions/workflows/ci.yml/runs?"
                    f"head_sha={SHA}&event=push&branch=main&per_page=100"
                )
            return result, summary_path.read_text(), calls, sleeps

    def test_pending_then_success(self):
        result, summary, calls, sleeps = self.run_poll([pages(pending()), pages(RUN)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((calls, sleeps), (2, ["30"]))
        self.assertIn("**PASSED:**", summary)
        self.assertNotIn("WAITING", summary)

    def test_pending_until_timeout(self):
        result, summary, calls, sleeps = self.run_poll([pages(pending())])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(calls, 21)
        self.assertEqual(sleeps, ["30"] * 20)
        self.assertIn("Timed out", summary)
        self.assertIn("workflow_dispatch", summary)

    def test_terminal_refusals_do_not_poll(self):
        for snapshot in (pages(), pages(dict(RUN, conclusion="failure")),
                         pages(dict(RUN, conclusion="cancelled")),
                         pages(dict(RUN, event="pull_request"))):
            with self.subTest(snapshot=snapshot):
                result, summary, calls, sleeps = self.run_poll([snapshot])
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual((calls, sleeps), (1, []))
                self.assertIn("**REFUSED:**", summary)

    def test_api_failure_refuses_with_summary(self):
        result, summary, calls, sleeps = self.run_poll([], api_failure=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((calls, sleeps), (1, []))
        self.assertIn("Could not read", summary)

    def test_malformed_evidence_refuses_with_summary(self):
        result, summary, _, _ = self.run_poll([{"message": "API error"}])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Invalid CI API evidence", summary)

    def test_invalid_run_id_refuses(self):
        run = copy.deepcopy(RUN)
        run["id"] = "not-an-id"
        result, summary, _, _ = self.run_poll([pages(run)])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Invalid CI run id", summary)

    def test_gate_position_and_both_entry_points(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        promote = workflow.split("\n  promote:\n", 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", promote)
        self.assertIn("needs.build-and-push.result == 'success'", promote)
        self.assertLess(promote.index("Check promotion eligibility"),
                        promote.index("Require successful CI"))
        self.assertLess(promote.index("Require successful CI"),
                        promote.index("docker/login-action"))
        self.assertLess(promote.index("Require successful CI"),
                        promote.index("Resolve and verify"))
        self.assertLess(promote.index("Resolve and verify"),
                        promote.index("Promote exact verified digests"))
        step = promote.split("      - name: Require successful CI", 1)[1]
        self.assertIn("if: steps.eligible.outputs.promote == 'true'",
                      step.split("        run: |", 1)[0])


if __name__ == "__main__":
    unittest.main()
