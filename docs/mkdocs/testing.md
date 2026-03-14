# Testing And Coverage

`containd` now has a repeatable local workflow for smoke, lint, security checks, fuzzing, benchmarks, and package coverage.

This page is not a claim that coverage is "done." It is the place contributors should start when they want to understand how much of the codebase is currently exercised and how to measure changes before a refactor or feature lands.

## Coverage Workflow

From the repo root:

```bash
bash scripts/coverage-report.sh
```

This runs:

```bash
go test ./... -covermode=count -coverprofile=/tmp/...
```

and prints:

- total statement coverage
- category averages
- the lowest-coverage packages in the repo

Useful options:

```bash
bash scripts/coverage-report.sh --top 20
bash scripts/coverage-report.sh --profile-out /tmp/containd.cover
bash scripts/coverage-report.sh --keep-artifacts
```

## Verification Integration

Coverage is intentionally optional in the broader verification pass because it is slower than the normal development loop.

To include it:

```bash
bash scripts/dev-verify.sh --with-coverage
```

That complements the other validation workflows:

- `bash scripts/dev-verify.sh --with-semgrep`
- `bash scripts/smoketest`
- `bash scripts/perf-baseline.sh`

## Current Shape

The current audit-refactor baseline is uneven:

- protocol parsers and several control-plane packages are in decent shape
- smoke and integration coverage are strong for forwarding, NAT, and the current Modbus/TCP DPI path
- CLI, management app, services, and some Linux-specific runtime packages still have much lighter direct statement coverage

This is expected for an appliance-style repo:

- some packages are exercised more through smoke/integration than direct unit coverage
- some Linux-only runtime packages are difficult to cover deeply on non-Linux hosts

That said, low direct coverage is still a signal. If you are changing one of the lowest-coverage packages, add focused tests while the code is fresh.

## What To Prioritize

The highest-value coverage additions are:

1. engine and management orchestration paths that currently rely mostly on smoke coverage
2. Linux-specific runtime packages like `netcfg`, `dhcpd`, and `conntrack`
3. service render/apply code paths
4. migration and rollback scenarios around config lifecycle
5. multi-packet parser behavior beyond the current fuzz and smoke baseline

## What Coverage Does Not Replace

Coverage is only one signal.

It does not replace:

- parser fuzzing
- smoke validation
- performance baselines
- security scans
- real lab-path testing

Treat `scripts/coverage-report.sh` as part of the audit toolbox, not the only quality gate.
