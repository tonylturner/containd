# Policy Model

Policy separates the configuration you are editing from the configuration the
engine runs:

- **Candidate** holds staged changes. Saving a rule or applying a template does
  not activate it.
- **Running** is the committed configuration. Commit validates candidate state
  and applies it; rollback restores a prior revision. Commit-confirmed requires
  confirmation within its timeout. See [Config Format](config-format.md).

## Firewall and DPI

Zone firewall rules use the Linux nftables backend. Rules are ordered and match
zones, CIDRs/assets, transport/port ranges, and optional identity, schedule, and
ICS predicates. Generic evaluation uses the firewall default action when nothing
matches. Actions are `ALLOW` or `DENY`.

### Identity and schedule predicates

containd does not yet enforce every identity or schedule predicate. A predicate
the deciding component cannot evaluate resolves toward denial:

- An `ALLOW` rule never matches on it, so the rule is inactive.
- A `DENY` rule matches as if the predicate always held.

Identity predicates are never evaluated: the dataplane does not attach
identities to flows. Schedules are evaluated only for ICS rules that NFQUEUE
steers to the engine (a nonzero `nfqueueGroup`). nftables decides every other
rule, so a scheduled `ALLOW` admits nothing and a scheduled `DENY` drops at all
times.

DPI mode resolves per-rule `ics.mode` > global `dpiMode` > `learn`. Learn is not a
global bypass: enforce-mode rules and independent kernel decisions can still
block traffic. IEC 104 uses a dedicated inspection envelope with default-deny
object evaluation, even if the generic firewall default is allow. See
[ICS predicates and modes](ics-dpi.md#ics-firewall-rule-predicates) and
[Enforcement](dataplane-enforcement.md).

Native [IDS rules](ids-rules.md) evaluate decoded events and generate alerts;
these are distinct from firewall decisions. Learned allowlist rules require
review, candidate staging, and commit.

## Templates and preview

The seven templates at `GET /api/v1/templates/ics` comprise two Modbus variants
and DNP3, S7comm, CIP, BACnet, and OPC UA examples, not one per supported protocol.
`POST /api/v1/templates/ics/apply` stages their rules. Purdue and maintenance
window templates belong to the general `/api/v1/templates` registry and its
`/apply` endpoint. The maintenance window template stages scheduled L4 `ALLOW`
rules, which are inactive (see
[Identity and schedule predicates](#identity-and-schedule-predicates)); its
maintenance access stays closed at all times.

Use `POST /api/v1/firewall/rules/preview` to inspect matches before committing;
preview is not a live packet-delivery test.

The admin-only `GET /api/v1/dataplane/ruleset` previews the candidate nftables
ruleset through the live engine, without applying it. It uses the candidate's
table, NFQUEUE and NFLOG settings and the engine's reserved management access.
The response and firewall page explain the IEC 104 envelope decision sampled
from current queue ownership. A later queue bind or loss can change steering
before commit. If the engine cannot compile, preview reports an error rather
than guessing with compiler defaults.
Preview does not enable enforcement or prove that a kernel apply will succeed.
When candidate enforcement is disabled, preview returns no nftables ruleset and
states plainly that enforcement is disabled and nothing would be applied.
