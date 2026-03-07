# IDS Rules (Sigma-like)

containd supports a small, Sigma-inspired IDS rule format that matches on normalized DPI events.

## Storage

Rules are persisted under the `ids` block in the main JSON config, and can also be authored/imported as standalone YAML for convenience.

## Standalone YAML schema

```yaml
version: 1
rules:
  - id: modbus-write-attempt
    title: Modbus write attempt
    description: Detect Modbus function codes that write coils/registers
    proto: modbus        # optional quick filter
    kind: request        # optional quick filter
    when:
      all:
        - field: attr.function_code
          op: in
          value: [5, 6, 15, 16]
    severity: high
    message: Modbus write detected
    labels:
      owner: ot
```

`when` supports:
- `all`: AND of child conditions
- `any`: OR of child conditions
- `not`: negation of a condition
- leaf: `{field, op, value}`

Leaf `op` values: `equals`, `contains`, `in`, `regex`, `gt`, `lt`.

Fields refer to normalized event fields:
- Core: `proto`, `kind`, `flowId`, `srcIp`, `dstIp`, `srcPort`, `dstPort`
- Attributes: prefix with `attr.` (e.g., `attr.function_code`, `attr.sni`, `attr.qname`)

## Sigma import

Use `pkg/cp/ids.ConvertSigmaYAML` or the CLI command:

```sh
containd convert sigma path/to/sigma-rule.yml > containd-ids.yaml
```

Supported Sigma subset:
- `title`, `id`, `description`, `level`, `tags`, `logsource`
- `detection` selections with field modifiers `|contains`, `|regex`/`|re`, `|startswith`, `|endswith`, `|gt`, `|lt`
- `condition` expressions with `and`, `or`, `not`, parentheses, and `selection*` wildcards

Tags may include `containd.proto.<proto>` or `containd.kind.<kind>` to set fast filters.
