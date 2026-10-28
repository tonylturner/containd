# Code Boundaries

This page defines ownership boundaries for contributor-facing files in `containd`.

Keep facade files small and domain logic near its route or feature. Use
`scripts/complexity-report.sh` during larger refactors to identify functions
that need decomposition.

## General Rules

- Treat top-level facade files as assembly points, not dumping grounds.
- When adding a new feature, put code in the domain file that matches the route family or UI feature first.
- If no domain file is a clean fit, create a new focused sibling module before adding unrelated logic to an existing large file.
- Keep request/session helpers separate from endpoint-specific methods.
- Keep page-level orchestration separate from large forms, modal flows, protocol metadata, and static lookup tables.

## HTTP API Boundaries

Primary facade:
- `api/http/server.go`

`server.go` should own:
- server construction
- dependency wiring
- route registration
- shared bootstrap helpers used across handler groups

`server.go` should not grow with new endpoint bodies. New handlers belong in focused sibling files such as:
- `*_handlers.go`
- `interface_autoassign.go`
- `cli_completion.go`
- `runtime_telemetry_handlers.go`
- `service_handlers.go`

Handler grouping rule:
- keep routes together by API domain, not by HTTP verb or by the page that happens to call them

Examples:
- interfaces and routing in interface/routing handler files
- IDS, signatures, learn mode in IDS-related handler files
- config backup/import/export in config backup handler files
- CLI completion tables and prompt hints in `cli_completion.go`, not back in `cli_handlers.go`

## Auth Boundaries

Primary auth facade:
- `api/http/auth.go`

`auth.go` should own:
- middleware assembly
- auth/session cookie helpers
- restricted-path policy

`auth.go` should keep auth flow split by mode:
- lab mode validation
- legacy token mode
- full session-backed auth mode

Rule:
- new auth branches should become small helper functions by mode or remediation policy, not more nested conditionals inside `authMiddleware`

## Engine Control API Boundaries

The engine's internal HTTP routes are registered in `pkg/app/engine/engine.go`.
Management-plane callers use the engine client in `api/engine/`. Keep engine control
handlers with the engine application, separate from the public management
API in `api/http/`.

## Config Model Boundaries

Primary model file:
- `pkg/cp/config/config.go`

`config.go` should own:
- core persisted config types
- redaction helpers
- schema-adjacent defaults and structural helpers

`config.go` should not own large validation implementations. Validation belongs in:
- `pkg/cp/config/validate.go`
- `pkg/cp/config/validate_assets.go`
- `pkg/cp/config/validate_services.go`

Rule:
- add new validation near the domain being validated, not back into `config.go`

## Parser And Fuzzing Boundaries

Protocol parsers are small, safety-sensitive modules. Keep parse entry points, malformed-packet regression tests, and fuzz targets colocated with the protocol package instead of hiding them in broad integration files.

Current parser layout examples:
- `pkg/dp/ics/dnp3/frame.go`
- `pkg/dp/ics/cip/frame.go`
- `pkg/dp/ics/iec104/asdu.go`
- `pkg/dp/itdpi/dns.go`
- `pkg/dp/itdpi/http.go`
- `pkg/dp/itdpi/tls.go`
- `pkg/dp/dpi/reassembly.go`

Placement rules:
- keep parser entry points in `frame.go`-style files
- keep malformed input regression tests beside the parser package in `*_test.go`
- keep fuzz targets beside the parser package in `fuzz_test.go`
- keep stream/reassembly fuzzing beside the shared reassembly implementation, not in protocol-specific packages

Examples:
- `pkg/dp/ics/modbus/fuzz_test.go`
- `pkg/dp/ics/dnp3/fuzz_test.go`
- `pkg/dp/ics/cip/fuzz_test.go`
- `pkg/dp/ics/iec104/fuzz_test.go`
- `pkg/dp/itdpi/fuzz_test.go`

Rule:
- when adding a new DPI or ICS parser, add its malformed-input tests and a focused fuzz target in the same package as part of the parser change

## UI API Client Boundaries

Primary facade:
- `ui/lib/api.ts`

`api.ts` should remain the stable import surface for pages and components.

`api.ts` should mostly:
- re-export auth/session helpers
- define shared API response/result types
- compose domain API modules into the exported `api` object

Domain files currently include:
- `ui/lib/api-core.ts`
- `ui/lib/api-request.ts`
- `ui/lib/api-auth.ts`
- `ui/lib/api-config.ts`
- `ui/lib/api-services.ts`
- `ui/lib/api-console.ts`
- `ui/lib/api-network.ts`
- `ui/lib/api-policy.ts`
- `ui/lib/api-firewall.ts` (rules, actions, warnings, counters, identity bindings)
- `ui/lib/api-dataplane.ts`
- `ui/lib/api-health.ts`, `ui/lib/api-service-status.ts`
- `ui/lib/api-ics-coverage.ts`, `ui/lib/api-iec104.ts`, `ui/lib/api-iec-pressure.ts`, `ui/lib/api-inventory.ts`
- `ui/lib/api-pcap.ts`
- `ui/lib/api-normalize.ts` (response normalizers)

Shared hooks live in `ui/hooks/` (`useHealth.ts` is the one health store that
the shell banner and pages subscribe to; `useSaveAction.ts` runs one save at
a time and owns pending state, toasts and the state line for settings pages).

Placement rules:
- session/base URL/auth state only in `api-core.ts`
- generic fetch/JSON/result helpers only in `api-request.ts`
- endpoint families in domain files named by feature area
- keep `api.ts` as the facade and re-export surface, not the place where new feature families get implemented

## Firewall Page Boundaries

Primary page:
- `ui/app/firewall/page.tsx`

Supporting modules in `ui/app/firewall/`: `firewall-rule-table.tsx`,
`firewall-rule-forms.tsx`, `firewall-rule-policy.ts` and
`firewall-rule-policy-fields.tsx`, `firewall-ics-fields.tsx`,
`firewall-rule-counters.tsx`, `firewall-rule-warnings.tsx`,
`firewall-ruleset-status.tsx`, `firewall-dpi-config.tsx`,
`firewall-dpi-modals.tsx` and `firewall-utils.ts`.

Rule:
- the page composes; each rule-editing concern lives in its own sibling

## Shell Boundaries

Primary page shell:
- `ui/components/Shell.tsx`

`Shell.tsx` should own:
- high-level layout
- session-check orchestration
- page chrome and shared top-level banners

Supporting modules:
- `ui/components/ProfileModal.tsx`
- `ui/components/shell-nav.tsx`

Rule:
- nav metadata, account modals, and other self-contained subflows should move to siblings once they become non-trivial

## SSH Console Boundaries

Primary SSH console files:
- `pkg/mp/sshserver/server_menu.go`
- `pkg/mp/sshserver/server_interactive.go`

`server_menu.go` should own:
- menu orchestration
- prompt flow composition
- per-menu action dispatch

`server_interactive.go` should own:
- shared interactive session helpers
- common prompt/output helpers
- audit helper glue for interactive flows

Rule:
- large prompt sequences such as setup wizards and diagnostics should be composed from small session methods, not rebuilt as inline closures

## Large Page Boundaries

Current examples:
- `ui/app/firewall/page.tsx`
- `ui/app/config/page.tsx`
- `ui/app/dataplane/page.tsx`
- `ui/app/vpn/page.tsx`

Current supporting modules:
- `ui/app/firewall/firewall-utils.ts`
- `ui/app/firewall/firewall-rule-forms.tsx`
- `ui/app/firewall/firewall-dpi-config.tsx`
- `ui/app/routing/routing-utils.ts`
- `ui/app/routing/routing-sections.tsx`
- `ui/app/vpn/vpn-openvpn-editor.tsx`
- `ui/app/config/config-block-explorer.tsx`

Page files should own:
- data fetching/orchestration for that page
- top-level state management
- composition of child forms, tables, cards, and modals

Page files should move out:
- protocol metadata tables
- large modal implementations
- large create/edit forms
- repeated helper logic

Recommended extraction pattern for large pages:
- `*-utils.ts` for lookup tables and pure helpers
- `*-forms.tsx` for create/edit forms
- `*-modals.tsx` for modal flows
- `*-sections.tsx` for repeated large page sections that are not modals or forms

## Performance And Benchmark Boundaries

Primary workflow:
- `scripts/perf-baseline.sh`

Primary docs:
- `docs/mkdocs/performance.md`

Placement rules:
- keep microbenchmarks adjacent to the package they measure in `*_bench_test.go`
- keep parser/reassembly fuzz targets adjacent to the package they harden in `fuzz_test.go`
- keep broad benchmark orchestration in `scripts/perf-baseline.sh`, not in ad hoc shell snippets in PRs or commit messages
- when a dataplane change touches parsing, reassembly, or decoder helpers, update the nearest benchmark/fuzz target in the same package if coverage would otherwise drift

Current examples:
- `pkg/dp/dpi/reassembly_bench_test.go`
- `pkg/dp/dpi/reassembly_fuzz_test.go`
- `pkg/dp/itdpi/bench_test.go`
- `pkg/dp/itdpi/fuzz_test.go`

## Review Checklist

Before merging a new feature, ask:

- Does this code belong in a facade or in a domain file?
- Is this adding another unrelated responsibility to a large file?
- Would a sibling module give this code a clearer responsibility?
- Is the new location obvious to the next contributor?

If the placement is unclear or adds unrelated responsibilities, split first
and then add the feature.

For ongoing maintenance, pair this document with:
- `scripts/complexity-report.sh` for complexity drift
- `scripts/dev-verify.sh --with-semgrep` for local structural/safety verification
- `scripts/coverage-report.sh` for coverage drift in refactored packages
- [Testing and Coverage](testing.md) for test selection and smoke workflows
- [Performance Baseline](performance.md) for dataplane benchmarks and profiles
