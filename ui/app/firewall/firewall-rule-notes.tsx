"use client";

import { useId, useState, type ReactNode } from "react";
import type { ShadowCounters } from "../../lib/api-shadow-counters";
import { TechnicalDetails } from "../../components/TechnicalDetails";
import type { CountersState } from "./firewall-rule-counters";

function CounterTime({ value }: { value: string }) {
  const date = new Date(value);
  return <time dateTime={value} title={value}>
    {Number.isNaN(date.getTime()) ? value : date.toLocaleString()}
  </time>;
}

/** Runtime causes lead; evaluation guidance and exact diagnostics stay available. */
export function FirewallRuleNotes({ counters, shadowCounters, children }: {
  counters: CountersState;
  shadowCounters: ShadowCounters | null;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const failure = counters && !counters.ok ? counters.error : null;
  const inactive = failure?.endsWith("nftables enforcement is not active");
  return <div role="group" aria-label="Rule table notes" className="border-b px-3 py-2 text-xs text-(--text-muted)">
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
      {counters && <div role="status" aria-label="Rule counters" className={failure ? "text-(--text-dim)" : undefined}>
        {counters.ok
          ? <>Hit counters since <CounterTime value={counters.data.since} />.</>
          : <>Hit counters unavailable. <span className="break-words text-(--text-muted)">{inactive ? "Firewall enforcement is not active." : failure}</span></>}
      </div>}
      <div role="status" aria-label="Shadow counters">
        {!shadowCounters ? "Loading monitor counts…" : !shadowCounters.available
          ? <>Monitor counts unavailable. <span className="break-words">{shadowCounters.reason}</span></>
          : <>Messages matched since <CounterTime value={shadowCounters.since} />.</>}
      </div>
      <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}
        className="whitespace-nowrap rounded-xs border bg-(--surface2) px-2 py-1 text-(--text)">
        How rules are evaluated
      </button>
    </div>
    <div id={id} hidden={!open} className="mt-2 space-y-2">
      {children}
      <p>Hit counters start when the running ruleset is applied; every apply restarts them at zero. Logging need not be on.</p>
      <p>Monitor counts reset when policy is applied or the inspection service restarts.
        Estimated allow/block for this rule only, not full-policy predictions.</p>
      {inactive && <TechnicalDetails>{failure}</TechnicalDetails>}
    </div>
  </div>;
}
