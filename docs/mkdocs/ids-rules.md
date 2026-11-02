# IDS Rules (Sigma-like)

Native IDS rules match normalized decoder `dpi.Event` values and produce alerts.
They are not firewall `ALLOW`/`DENY` rules or automatic IPS actions.

## Rule workspace

The **Rules** list comes first and stays visible while using the other tools.
Search, filters, sorting, pagination, selection, bulk actions and **Edit**
remain in the list. **Edit** opens common rule fields: ID, title, description,
message, protocol, event kind, severity, enablement, addresses and ports, and a
single event-field condition with a typed value. **Edit JSON** is the advanced
path for compound/list conditions, labels, content matches, YARA strings and
other metadata; unedited fields are preserved in either path.
**Save rule** stages the rule and any other current IDS page edits in one
revision-guarded save. No additional page **Save** is needed. Review and commit
to apply. Toggle, deletion, group and Sigma conversion edits still use page **Save**.
You can start a new rule draft while a page save is pending, but cannot submit
a second save until the first finishes. The earlier save cannot acknowledge
that newer draft. If a dialog stays open after a successful save, its success
notice remains visible inside the dialog.
**Add/import rules** has the **Import** control for both
file import and **Convert & Add** of pasted Sigma YAML. Opening it performs no
import, selection, save or commit.

**Manage groups** contains the **Groups** disclosure. Saved groups open it by
default; a count remains visible when closed. The **Filter** text field preserves
the exact matching expression, with syntax help in **Advanced group matching**.
The group form also saves an optional **Description**, shown beside saved groups.
**Export** and **Sources** are secondary tools below the list. At export the UI
states **Export uses active committed rules**: candidate changes are not included.
If a configuration refresh fails, retained rules, group details, filters,
**Export** and **Sources** remain inspectable; configuration edits stay disabled
until the configuration can be read again.

## Storage and staging

Rules live in the main JSON configuration's `ids` block. Use
`GET /api/v1/ids/rules` to read candidate IDS configuration and
`POST /api/v1/ids/rules` to stage it. Review existing rules before replacing the
rule list, then commit with `POST /api/v1/config/commit`.
See [Config Format](config-format.md) and [API Reference](api-reference.md).

Example IDS configuration body (replace the rule list only intentionally):

```json
{
  "enabled": true,
  "rules": [
    {
      "id": "modbus-write-attempt",
      "title": "Modbus write attempt",
      "description": "Detect writes to coils or registers",
      "proto": "modbus",
      "kind": "request",
      "when": {
        "all": [
          {"field": "attr.function_code", "op": "in", "value": [5, 6, 15, 16]}
        ]
      },
      "severity": "high",
      "message": "Modbus write detected",
      "labels": {"owner": "ot"}
    }
  ]
}
```

## Evaluator fields and conditions

`when` supports `all` (AND), `any` (OR), `not` (negation), and leaves
`{field, op, value}`. Leaf operations are `equals`, `contains`, `in`, `regex`,
`gt`, and `lt`.

- Core fields: `proto`, `kind`, and `flowId` (field lookup is case-insensitive).
- Attributes: `attr.<key>`, such as `attr.function_code`, `attr.unit_id`,
  `attr.sni`, or `attr.qname`. Attribute names must match emitted keys; inspect
  actual events rather than assuming every decoder supplies every field.
- A bare non-core name falls back to an attribute lookup.

Source/destination IP and port are **not core IDS fields**. They are added to the
telemetry envelope after decoding; the evaluator receives the original decoder
event, not that enriched envelope. Use firewall network predicates for network
scope rather than assuming `srcIp`, `dstIp`, `srcPort`, or `dstPort` work here.
Some decoders do emit `attr.src_port` and `attr.dst_port`; the Sigma converter
maps `srcport`/`dstport` to those attributes. That does not provide source or
destination IP matching, and availability still depends on the decoder.

## Conversion and import

`POST /api/v1/ids/convert/sigma` accepts `{"sigmaYAML": "..."}` and returns one
normalized JSON rule without staging it.

The appliance CLI registry also provides:

```text
convert sigma /path/to/sigma-rule.yml
```

That command reads files in the appliance process's filesystem and writes a
native YAML conversion result. It is not a top-level binary subcommand, and its
native YAML output is **not** accepted by `/api/v1/ids/import`. For programmatic use,
`pkg/cp/ids.ConvertSigmaYAML` returns a normalized rule and
`WriteConvertedSigma` writes the CLI's YAML bundle.

`POST /api/v1/ids/import` accepts a multipart `file` and optional `format`:
`sigma`, `suricata`, `snort`, or `yara`. Import stages converted rules, skips
existing IDs, and requires commit to activate them. Native standalone YAML is
not a supported import format. These converters implement subsets, not complete
compatibility with the source engines. Inspect conversion notes and evaluability
before enabling imported rules.

Suricata and Snort imports infer `iec104` for rules with numeric port 2404,
including rules using `tcp`, `ip`, or port 2404 on either endpoint. Other ports
continue to use the general transport or their known-protocol mapping.

The supported Sigma subset includes metadata (`title`, `id`, `description`,
`level`, `tags`, `logsource`), detection selections with `|contains`, `|regex`/`|re`,
`|in`, `|gt`, `|lt`, equality lists (membership), and conditions using `and`, `or`, `not`,
parentheses, and `selection*` wildcards. Tags `containd.proto.<proto>` and
`containd.kind.<kind>` set fast filters.

## Export

`GET /api/v1/ids/export?format=snort` downloads **running** rules, not the
candidate. Supported formats are `snort`, `suricata` (the default), `sigma`,
and `yara`. For a native JSON backup, use `GET /api/v1/ids/backup`.

Snort 3 and Suricata rules-file exports refuse a rule rather than drop a
predicate. The current conservative mapping is:

| Native input | Rules-file export |
| --- | --- |
| Empty protocol, `ip`, `tcp`, `udp`, `icmp` | Corresponding header (`ip` when empty), retaining network addresses and ports |
| `contentMatches` | Content, negation, case and position modifiers; Snort 3 uses comma-separated modifiers |
| Application protocols: `modbus`, `dnp3`, `cip`, `iec104`, HTTP, DNS, TLS, SSH, FTP, SMTP | Refused; decoder-event semantics are not assumed equivalent to a target service inspector |
| Removed or unknown protocols (including native `enip`) | Refused |
| `kind`, any `when` predicate or Boolean condition tree | Refused, including service, Modbus function/unit/data, DNP3 function/object/indications and CIP service/class/instance/attribute tests |
| Cross-format imported rules or YARA predicates | Refused; their unrepresented source predicates cannot safely be discarded |
| Imported rules without valid cached source | Native regeneration only when exact; conversion notes or non-evaluable guards prevent discarding unrepresented predicates |
| Empty/multiline content, non-byte-pair hex, literal pipes in text content, negative depth/offset/within | Refused; use explicit hex bytes for literal pipes |
| Disabled rules | Refused rather than activated in the exported file |
| Same-format import with `rawSource` | Re-imported and returned unchanged only when its predicates still agree; otherwise native regeneration or a named refusal |

The content/header vocabulary is described in the
[Snort 3 rule-writing guide](https://docs.snort.org/rules/headers/)
and its [content options](https://docs.snort.org/rules/options/payload/content),
and the [Suricata rules guide](https://docs.suricata.io/en/latest/rules/).
Application option names alone do not establish equivalent decoder behavior;
there are currently no native application-predicate mappings.

The response stays a file attachment, even when every rule is refused.
`X-Containd-IDS-Refused` gives the refused count (zero for a complete export).
All formats begin with a comment for each refusal, containing JSON
`{"rule_id":"...","reason":"..."}` after `# refused: ` (`// refused: ` for YARA).
No refused rule is emitted as an active rule. The Export panel shows the count
after download; inspect the comments before installing the file in another engine.

Sigma and YARA use the same preserve-or-refuse policy:

- **Sigma:** native rules export to **containd's own Sigma dialect**, not a
  third-party backend schema. Decoder-backed `attr.<key>` fields map to `<key>`;
  core `proto`, `kind` and `flowid` fields retain their names. Equality has no
  modifier; `contains`, `regex`, `gt`, `lt` and scalar `in` retain their modifiers.
  List `in` values become YAML lists without a modifier. Boolean `all`, `any`
  and `not` become parenthesized `and`, `or` and `not` expressions with unique
  selections. The default equality operator and singleton groups retain their
  matching meaning even though their serialized shape changes.
  Protocol and kind quick filters use `containd.proto.<proto>` and
  `containd.kind.<kind>` tags, which containd's importer enforces. These tags
  **do not enforce filters in arbitrary third-party Sigma consumers**.
  Severity, `logsource`, status, references and tags are retained; current quick
  filters replace stale protocol/kind metadata tags.
  Byte matches, network address/port quick filters, fields outside the decoder
  vocabulary, unmapped operations, and value shapes that would import
  differently are refused. A native empty `when` is also refused: the importer
  treats empty detections as non-evaluable, not match-all.
  UTF-8 imports retain each document's original bytes, including comments,
  directives and line endings. Multi-rule downloads remove per-document UTF-8
  BOM markers when joining documents; single-source exports remain unchanged.
  UTF-16 imports are re-encoded to independent UTF-8 documents: later source
  slices lack the stream's encoding BOM, and non-UTF-8 bytes cannot survive
  native rules' JSON storage.
  Exports of these imports therefore use UTF-8, not the original UTF-16 bytes.
  Original source is returned unchanged while its matching predicates and
  severity agree with the normalized rule. Edited rules use the native inverse
  when their cached source is stale or corrupt; predicates without an inverse
  are refused rather than exporting their old values.
- **YARA:** pure `yaraStrings` content definitions and their `yara.condition`
  expression are exported (default: `any of them`). Valid, equivalent cached
  YARA source remains unchanged. Any protocol, kind, `when`, network scope or
  network `contentMatches` predicate is refused, including when attached to original
  YARA source. Metadata-only rules are refused.
  Synthesized rules accept literal hex byte pairs without modifiers and regex
  patterns without delimiter slashes or newlines; unsupported syntax is refused.
  Conditions must be a single expression, not additional rule source.

Disabled rules are refused in every format. In all four formats, `rawSource` is
an export cache, not an override for edited predicates. Before reuse, containd
re-imports the source with that format's converter and compares event conditions,
quick filters, network scope, byte matches and modifiers, YARA conditions, action,
severity and matching guards. Equivalent source is returned byte for byte. A
parse failure or difference falls through to native export, which either keeps
the current predicates or reports a refusal naming what it cannot preserve.
Conversion notes and non-evaluable guards are not cleared to make regeneration
succeed. YARA imports carry such guards, so an invalidated YARA cache is refused
when its native representation cannot be exported exactly. Formatting and
non-predicate metadata may remain as in the original source while its cache is
valid; use the JSON backup for the complete normalized rule record.
