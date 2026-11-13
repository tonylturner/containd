# Published-image upgrade smoke

Build the exact candidate from the repository root, then run the whole matrix:

```sh
docker build -f build/Dockerfile.mgmt -t containd/containd:upgrade-local .
UPGRADE_IMAGE=containd/containd:upgrade-local \
  COMPOSE_PROJECT_NAME=upgrade-local-$(date +%s) \
  bash scripts/smoke-upgrade.sh
```

Requires Docker Engine 28.1+, Compose 2.36.0+, Python 3 and Internet access for
published images and the small Python endpoint image. No running appliance is
used. The candidate must already exist locally. The default evidence directory
is `build/<project>`; `UPGRADE_RESULTS` can select another **new** directory.
Evidence contains credentials, private keys, full stopped-data backups and logs;
keep it private and dispose of it according to your credential-retention policy.

The matrix is training 0.1.30–0.1.42 and strict→strict 0.1.39–0.1.42. Each row
pulls its genuine published image, boots fresh private data, rotates bootstrap
credentials, creates admin/view accounts and saves distinct previous, running
and uncommitted candidate configurations. The representative policy has two
zones, bound interfaces, default deny, an explicit TCP allow and deny, a Modbus
mode migration sentinel and a custom IDS rule bank. Unrelated services are off.
Historical pre-0.1.37 seeding uses the old API without invented revision headers;
all newer config writes chain actual revision acknowledgements.

Before first candidate boot the old writer stops, the entire data tree is
backed up, and pre-0.1.41 attachments change from `ethN` to saved row names.
The driver checks migrated configuration, accounts, IDs, roles, profile/MFA
flags, TLS/SSH identity, valid CAS with a retained epoch where one existed,
revision-bound ready/protecting status and receiver-verified cross-zone traffic.
It repeats protection/traffic after a clean restart and a new candidate commit.
The restart must not change config, banks, CAS, running generation or migration
audit records. The target schema is read from `SchemaVersionCurrent`, never
inferred from a release number.

Each row has fresh data; only that invocation's project is torn down, including
on failures. Subnets are selected after checking existing Docker network IPAM,
management publishes only ephemeral loopback ports, and engine/SSH are not
published. Existing project resources or evidence directories are refused.
`matrix.json` records each executed row's result, wall seconds and named assertion
count. `remaining-resources.json` must show empty containers/networks/volumes.
A failure stops the matrix and returns nonzero; no missing row is a pass.
Images are kept. This covers combined mode, not a split-process or arbitrary
service/configuration upgrade, pending MFA challenges, or live session retention.

For a focused reproduction (not a complete release gate):

```sh
UPGRADE_IMAGE=containd/containd:upgrade-local \
  bash scripts/smoke-upgrade.sh --from-version 0.1.35 --profile training
```

`scripts/smoke-rule-modes-migration.sh` is a focused wrapper for that row using
`RULE_MODES_IMAGE` and optional `RULE_MODES_RESULTS`. There is only one lifecycle
and teardown implementation.

Offline fixture/assertion checks:

```sh
python3 -m unittest discover -s test/upgrade -p '*_test.py'
bash -n scripts/smoke-upgrade.sh scripts/smoke-rule-modes-migration.sh
shellcheck scripts/smoke-upgrade.sh scripts/smoke-rule-modes-migration.sh
```
