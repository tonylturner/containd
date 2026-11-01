import type { ReactNode } from "react";
import type { FirewallRule } from "../../lib/api";
import type { ShadowCounters } from "../../lib/api-shadow-counters";
import { ShadowCountersCell } from "../ics/ics-shadow-counters";
import { summarizeIEC104 } from "../ics/iec104";
import { formatICSMode, summarizeGenericICS } from "../ics/ics-shared";
import { RuleCountersCell, type CountersState } from "./firewall-rule-counters";
import { formatSchedule } from "./firewall-rule-policy";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return <div className="min-w-0">
    <dt className="mb-1 font-semibold text-(--text)">{label}</dt>
    <dd className="break-words text-(--text-muted)">{children}</dd>
  </div>;
}

/** Exact matching values and telemetry, without changing the rule or its position. */
export function FirewallRuleDetail({ rule, dpiMode, counters, shadowCounters }: {
  rule: FirewallRule;
  dpiMode?: string;
  counters: CountersState;
  shadowCounters: ShadowCounters | null;
}) {
  return <dl aria-label={`Details of ${rule.id}`} className="grid min-w-0 gap-4 text-xs sm:grid-cols-2 lg:grid-cols-3">
    <Field label="Conditions">
      <div>sources CIDR: <span className="font-mono">{rule.sources?.join(", ") || "any"}</span></div>
      <div>destinations CIDR: <span className="font-mono">{rule.destinations?.join(", ") || "any"}</span></div>
      {!!rule.viaForwards?.length && <div>via <span className="font-mono">{rule.viaForwards.join(", ")}</span></div>}
      {!!rule.identities?.length && <div>identity <span className="font-mono">{rule.identities.join(", ")}</span></div>}
      {rule.schedule && <div>schedule {formatSchedule(rule.schedule)}</div>}
    </Field>
    <Field label="ICS Filter">
      {rule.ics?.protocol ? <>
        <div>{formatICSMode(rule.ics.mode, dpiMode).label}</div>
        <div>{rule.ics.protocol === "iec104"
          ? `iec104 ${summarizeIEC104(rule.ics).types} ${summarizeIEC104(rule.ics).addresses}`
          : `${rule.ics.protocol} ${summarizeGenericICS(rule.ics)}`}</div>
        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono">{JSON.stringify(rule.ics, null, 2)}</pre>
      </> : "—"}
    </Field>
    <Field label="Hits"><RuleCountersCell rule={rule} counters={counters} /></Field>
    <Field label="Shadow matches"><ShadowCountersCell rule={rule} globalMode={dpiMode} counters={shadowCounters} /></Field>
    <Field label="Log">{rule.log ? "on" : "off"}</Field>
    <Field label="Exact matching values">
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono">{JSON.stringify({
        sourceZones: rule.sourceZones ?? [], destZones: rule.destZones ?? [], protocols: rule.protocols ?? [],
        ...(rule.schedule ? { schedule: rule.schedule } : {}),
      }, null, 2)}</pre>
    </Field>
  </dl>;
}
