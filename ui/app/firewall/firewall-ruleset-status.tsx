import type { RulesetEngineStatus } from "../../lib/api";

/** A readable local time; Go's zero time and blanks read as absent. */
export function formatStatusTime(value: string | undefined): string | null {
  if (!value) return null;
  const t = new Date(value);
  if (Number.isNaN(t.getTime())) return value;
  return t.getUTCFullYear() < 2000 ? null : t.toLocaleString();
}

const amber = "rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-amber";

/**
 * The ruleset the engine has in force, a failed apply that left it in force,
 * and the schedule planner that keeps its time windows filled.
 */
export function AppliedRulesetStatus({ status }: { status: RulesetEngineStatus }) {
  const appliedAt = formatStatusTime(status.appliedAt);
  const failedAt = formatStatusTime(status.failedAt);
  const planner = status.schedulePlanner;
  return (
    <section aria-label="Applied ruleset" className="mt-3 space-y-2 text-xs">
      <p className="text-(--text-muted)">
        {appliedAt
          ? <>Applied ruleset: in force since {appliedAt}{status.snapshotVersion && <> (snapshot <span className="font-mono">{status.snapshotVersion}</span>)</>}.</>
          : "Applied ruleset: none in force yet."}
      </p>
      {status.error && (
        <div role="status" aria-label="Failed apply" className={amber}>
          <p className="font-semibold">
            Last apply failed{failedAt && <> at {failedAt}</>}
            {status.failedSnapshotVersion && <> (snapshot <span className="font-mono">{status.failedSnapshotVersion}</span>)</>}
          </p>
          <p className="wrap-break-word">{status.error}</p>
          <p>{appliedAt ? "The ruleset applied before it stays in force until an apply succeeds." : "No ruleset is in force."}</p>
        </div>
      )}
      {planner && <SchedulePlanner planner={planner} />}
    </section>
  );
}

function SchedulePlanner({ planner }: { planner: NonNullable<RulesetEngineStatus["schedulePlanner"]> }) {
  const horizon = formatStatusTime(planner.horizonEnd);
  const refill = formatStatusTime(planner.lastRefill);
  const errorAt = formatStatusTime(planner.lastErrorAt);
  const window = <>Schedule windows planned until {horizon ?? "—"} (last refill {refill ?? "—"}).</>;
  if (planner.state !== "degraded") {
    return (
      <p role="status" aria-label="Schedule planner" className="text-(--text-muted)">
        Schedule planner: ok. {window}
      </p>
    );
  }
  return (
    <div role="status" aria-label="Schedule planner" className={amber}>
      <p className="font-semibold">Schedule planner degraded{planner.reason && <>: {planner.reason}</>}</p>
      <p>{window} Past that time a scheduled ALLOW stops matching and a scheduled DENY applies.</p>
      {planner.lastError && <p className="wrap-break-word">Last refill error{errorAt && <> at {errorAt}</>}: {planner.lastError}</p>}
    </div>
  );
}
