# IDS Rules (Sigma-like)

Native IDS rules match normalized decoder `dpi.Event` values and produce alerts.
They are not firewall `ALLOW`/`DENY` rules or automatic IPS actions.

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
native YAML output is **not** accepted by `/ids/import`. For programmatic use,
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
`|startswith`, `|endswith`, `|gt`, `|lt`, and conditions using `and`, `or`, `not`,
parentheses, and `selection*` wildcards. Tags `containd.proto.<proto>` and
`containd.kind.<kind>` set fast filters.

## Export

`GET /api/v1/ids/export?format=snort` downloads **running** rules, not the
candidate. Supported formats are `snort`, `suricata` (the default), `sigma`,
and `yara`. For a native JSON backup, use `GET /api/v1/ids/backup`.

Snort 3 rules-file exports refuse a rule rather than drop a
predicate. The current conservative mapping is:

| Native input | Rules-file export |
| --- | --- |
| Empty protocol, `ip`, `tcp`, `udp`, `icmp` | Corresponding header (`ip` when empty), retaining network addresses and ports |
| `contentMatches` | Content, negation, case and position modifiers; Snort 3 uses comma-separated modifiers |
| Application protocols: `modbus`, `dnp3`, `cip`, `iec104`, HTTP, DNS, TLS, SSH, FTP, SMTP | Refused; decoder-event semantics are not assumed equivalent to a target service inspector |
| Removed or unknown protocols (including native `enip`) | Refused |
| `kind`, any `when` predicate or Boolean condition tree | Refused, including service, Modbus function/unit/data, DNP3 function/object/indications and CIP service/class/instance/attribute tests |
| Cross-format imported rules or YARA predicates | Refused; their unrepresented source predicates cannot safely be discarded |
| Disabled rules | Refused rather than activated in the exported file |
| Same-format import with `rawSource` | Original source returned unchanged (unless disabled); normalized fields are not merged into it |

The content/header vocabulary is described in the
[Snort 3 rule-writing guide](https://docs.snort.org/rules/headers/)
and its [content options](https://docs.snort.org/rules/options/payload/content),
and the [Suricata rules guide](https://docs.suricata.io/en/latest/rules/).
Application option names alone do not establish equivalent decoder behavior;
there are currently no native application-predicate mappings.

The response stays a file attachment, even when every rule is refused.
`X-Containd-IDS-Refused` gives the refused count (zero for a complete export).
Rules files begin with a comment for each refusal, containing JSON
`{"rule_id":"...","reason":"..."}` after `# refused: `. No refused rule is
emitted as an active rule. The Export panel shows the count after download;
inspect the comments before installing the file in another engine.

Sigma and YARA exports retain their existing conversion behavior; they are not
covered by the rules-file semantic-equivalence guarantee. Same-format
`rawSource` is authoritative: to edit an imported rule's source semantics,
edit and reimport the original source rather than expecting normalized edits
to rewrite it.
