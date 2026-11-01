"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { getShadowCounters, type ShadowCounters } from "../../lib/api-shadow-counters";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import type { FirewallRule } from "../../lib/api";
import { formatICSMode } from "./ics-shared";

export function useShadowCounters() {
  const [counters, setCounters] = useState<ShadowCounters | null>(null);
  const generation = useRef(0);
  const reload = useCallback(async () => {
    const current = ++generation.current;
    const result = await getShadowCounters();
    if (generation.current === current) setCounters(result);
  }, []);
  useConfigRefresh(reload);
  useEffect(() => {
    const requests = generation;
    void reload();
    const timer = setInterval(() => { if (!document.hidden) void reload(); }, 10000);
    return () => { clearInterval(timer); requests.current++; };
  }, [reload]);
  return { counters, reload };
}

export function ShadowCountersNote({ counters }: { counters: ShadowCounters | null }) {
  return <div role="status" aria-label="Shadow counters" className="mb-2 text-xs text-(--text-muted)">
    {!counters ? "Loading monitor counts…" : !counters.available
      ? <>Monitor counts unavailable. <span className="break-words">{counters.reason}</span></>
      : <>Messages matched since <time dateTime={counters.since}>{counters.since}</time>.
        Reset when policy is applied or the inspection service restarts. Estimated allow/block for this rule only, not full-policy predictions.</>}
  </div>;
}

export function ShadowCountersCell({ rule, globalMode, counters }: {
  rule: FirewallRule; globalMode?: string; counters: ShadowCounters | null;
}) {
  if (!rule.ics?.protocol) return <>—</>;
  const count = counters?.available ? counters.rules.find((r) => r.ruleId === rule.id) : undefined;
  const monitor = formatICSMode(rule.ics.mode, globalMode).effectiveMode === "monitor";
  if (!monitor && !count) return <>—</>;
  const params = new URLSearchParams({ kind: "ics.decision", ruleId: rule.id, mode: "monitor" });
  return <div aria-label={`Shadow matches of ${rule.id}`} className="space-y-1 text-xs">
    {!counters ? <span>Loading…</span> : !counters.available ? <span>unavailable</span> : !count
      ? <span title="This candidate monitor rule is absent from the installed monitor partition.">not applied yet</span>
      : <>
        <div>{count.shadowMatches.toLocaleString()} messages</div>
        <div>{count.wouldAllow.toLocaleString()} would allow · {count.wouldDeny.toLocaleString()} would deny</div>
      </>}
    <Link href={`/events/?${params}`} className="block text-(--amber) hover:underline">Monitor events</Link>
  </div>;
}
