#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Decide promotion from paginated GitHub workflow-runs JSON on stdin.

Exit 0 permits promotion, 1 refuses, and 3 requests another bounded poll.
The caller must fetch the ci.yml workflow endpoint, not repository-wide runs.
"""

import argparse
import json
import re
import sys
from pathlib import Path


PENDING = {"queued", "in_progress", "requested", "waiting", "pending"}


def decide(pages, commit, repository, final_check=False):
    """Return (exit code, Markdown evidence); no network or clock access."""
    lines = ["### Release CI gate", "", f"Source commit: `{commit}`.", ""]
    runs = []
    for page in pages:
        for run in page["workflow_runs"]:
            if (
                run.get("head_sha") == commit
                and run.get("event") == "push"
                and run.get("head_branch") == "main"
                and run.get("name") == "CI"
            ):
                for field in ("id", "run_number", "run_attempt"):
                    if type(run[field]) is not int or run[field] < 1:
                        raise ValueError(f"Invalid CI run {field}")
                runs.append(run)

    if not runs:
        lines.append("**REFUSED:** No CI run for this exact commit from a push to main.")
        return 1, "\n".join(lines) + "\n"

    # A new run supersedes older runs; a re-run supersedes its earlier attempts.
    # Never pick an older green result while a newer run/attempt is red or pending.
    run = max(runs, key=lambda r: (r["run_number"], r["run_attempt"], r["id"]))
    url = f"https://github.com/{repository}/actions/runs/{run['id']}"
    status, conclusion = run["status"], run["conclusion"]
    lines.extend([
        f"CI run: [{run['id']}]({url}), attempt {run['run_attempt']}.",
        f"Event: `push`; branch: `main`; status: `{status}`; "
        f"conclusion: `{conclusion or 'none'}`.",
        "",
    ])
    if status == "completed" and conclusion == "success":
        lines.append("**PASSED:** Exact-commit CI succeeded; promotion may continue.")
        code = 0
    elif status in PENDING and not final_check:
        lines.append("**WAITING:** Exact-commit CI has not completed.")
        code = 3
    elif status in PENDING:
        lines.append(
            "**REFUSED:** Timed out waiting for exact-commit CI. "
            "Re-run the Release workflow_dispatch with the same tag after CI finishes."
        )
        code = 1
    else:
        lines.append("**REFUSED:** Exact-commit CI did not complete successfully.")
        code = 1
    return code, "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--final-check", action="store_true")
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{40}", args.commit):
        parser.error("--commit must be a full peeled commit SHA")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("--repository must be OWNER/REPO")
    try:
        code, evidence = decide(
            json.load(sys.stdin), args.commit, args.repository, args.final_check
        )
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        code = 1
        evidence = f"### Release CI gate\n\n**REFUSED:** Invalid CI API evidence: {error}\n"
    print(evidence, end="")
    if code != 3:
        with args.summary.open("a") as summary:
            summary.write(evidence + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
