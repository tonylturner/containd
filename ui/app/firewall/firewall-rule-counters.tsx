import type { ApiResult, FirewallRule, RuleCount, RuleCounters } from "../../lib/api";
import { formatBytes } from "../../lib/utils";

/** Counters of the applied ruleset: loading (null), unavailable, or loaded. */
export type CountersState = ApiResult<RuleCounters> | null;

function formatCount(n: number): string {
  return n.toLocaleString();
}

function hitsLabel(rule: FirewallRule, count: RuleCount): string {
  return rule.action === "TAG"
    ? `${formatCount(count.packets)} conns`
    : `${formatCount(count.packets)} pkts`;
}

/** One rule's packets and bytes, plus excess drops of a RATE_LIMIT rule. */
export function RuleCountersCell({ rule, counters, compact = false }: { rule: FirewallRule; counters: CountersState; compact?: boolean }) {
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
    <div aria-label={`${compact ? "Hit summary" : "Hits"} of ${rule.id}`} className="whitespace-nowrap text-xs">
      <div className="font-mono text-(--text)">{hitsLabel(rule, count)}</div>
      {!compact && <div className="font-mono text-(--text-muted)">{formatBytes(count.bytes)} <span>({formatCount(count.bytes)} bytes)</span></div>}
      {count.excessDrops !== undefined && (!compact || count.excessDrops > 0) && (
        <div className={`font-mono ${count.excessDrops > 0 ? "text-amber" : "text-(--text-muted)"}`}>
          {formatCount(count.excessDrops)} over limit
        </div>
      )}
    </div>
  );
}
