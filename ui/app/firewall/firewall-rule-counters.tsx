import type { ApiResult, FirewallRule, RuleCount, RuleCounters } from "../../lib/api";
import { formatBytes } from "../../lib/utils";
import { TechnicalDetails } from "../../components/TechnicalDetails";

/** Counters of the applied ruleset: loading (null), unavailable, or loaded. */
export type CountersState = ApiResult<RuleCounters> | null;

function formatCount(n: number): string {
  return n.toLocaleString();
}

/**
 * When the counters started, or why there are none. Counters are runtime
 * telemetry: an engine without an applied ruleset is a quiet state, not an
 * error.
 */
export function RuleCountersNote({ counters }: { counters: CountersState }) {
  if (!counters) return null;
  if (!counters.ok) {
    return (
      <div role="status" aria-label="Rule counters" className="mb-2 text-xs text-(--text-dim)">
        Hit counters unavailable.
        <TechnicalDetails>{counters.error}</TechnicalDetails>
      </div>
    );
  }
  const since = new Date(counters.data.since);
  return (
    <p role="status" aria-label="Rule counters" className="mb-2 text-xs text-(--text-muted)">
      Hit counters since {Number.isNaN(since.getTime()) ? counters.data.since : since.toLocaleString()}, when the
      running ruleset was applied; every apply restarts them at zero. Logging need not be on.
    </p>
  );
}

function hitsLabel(rule: FirewallRule, count: RuleCount): string {
  return rule.action === "TAG"
    ? `${formatCount(count.packets)} conns`
    : `${formatCount(count.packets)} pkts`;
}

/** One rule's packets and bytes, plus excess drops of a RATE_LIMIT rule. */
export function RuleCountersCell({ rule, counters }: { rule: FirewallRule; counters: CountersState }) {
  if (!counters?.ok) return <span className="text-xs text-(--text-dim)">&mdash;</span>;
  const count = counters.data.rules.find((c) => c.ruleId === rule.id);
  if (!count) {
    return (
      <span className="text-xs text-(--text-dim)" title="This rule is not in the applied ruleset; commit to apply it.">
        not applied
      </span>
    );
  }
  return (
    <div aria-label={`Hits of ${rule.id}`} className="whitespace-nowrap text-xs">
      <div className="font-mono text-(--text)">{hitsLabel(rule, count)}</div>
      <div className="font-mono text-(--text-muted)">{formatBytes(count.bytes)}</div>
      {count.excessDrops !== undefined && (
        <div className={`font-mono ${count.excessDrops > 0 ? "text-amber" : "text-(--text-muted)"}`}>
          {formatCount(count.excessDrops)} over limit
        </div>
      )}
    </div>
  );
}
