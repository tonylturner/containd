import type { InstalledRulesetStatus } from "../../lib/api";
import type { InstalledRulesetView } from "../../hooks/useInstalledRuleset";
import { TechnicalDetails } from "../../components/TechnicalDetails";

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
export function AppliedRulesetStatus({ status }: { status: InstalledRulesetStatus }) {
  const appliedAt = status.installed ? formatStatusTime(status.appliedAt) : null;
  return (
    <section aria-label="Applied ruleset" className="mt-3 space-y-2 text-xs">
      <p className="text-(--text-muted)">
        {status.installed
          ? <>Applied ruleset: in force{appliedAt && <> since {appliedAt}</>}.</>
          : "Applied ruleset: none in force."}
      </p>
      {status.installed && status.snapshotVersion && <TechnicalDetails>Configuration ID: <span className="font-mono">{status.snapshotVersion}</span></TechnicalDetails>}
      <RulesetFaults status={status} />
      {status.schedulePlanner && status.schedulePlanner.state !== "degraded" && <SchedulePlanner planner={status.schedulePlanner} />}
    </section>
  );
}

/**
 * Only what needs attention: a failed apply and a degraded schedule planner,
 * the reasons health reports enforcement degraded. Nothing when neither.
 */
export function RulesetFaults({ status }: { status: InstalledRulesetStatus }) {
  const failedAt = formatStatusTime(status.failedAt);
  const planner = status.schedulePlanner?.state === "degraded" ? status.schedulePlanner : undefined;
  if (!status.error && !planner) return null;
  return (
    <>
      {status.error && (
        <div role="status" aria-label="Failed apply" className={amber}>
          <p className="font-semibold">
            Last apply failed{failedAt && <> at {failedAt}</>}
          </p>
          <p>{status.installed ? "The ruleset applied before it stays in force until an apply succeeds." : "No ruleset is in force."}</p>
          <TechnicalDetails>
            {status.failedSnapshotVersion && <p>Failed configuration ID: <span className="font-mono">{status.failedSnapshotVersion}</span></p>}
            <p>{status.error}</p>
          </TechnicalDetails>
        </div>
      )}
      {planner && <SchedulePlanner planner={planner} />}
    </>
  );
}

/** Why the installed status is missing; nothing while it loads or once loaded. */
export function InstalledRulesetUnavailable({ view }: { view: InstalledRulesetView }) {
  if (view.state !== "unavailable") return null;
  return (
    <div role="status" aria-label="Installed ruleset status" className="mt-3 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
      Installed ruleset status unavailable. Check appliance health.
      <TechnicalDetails>{view.error}</TechnicalDetails>
    </div>
  );
}

function SchedulePlanner({ planner }: { planner: NonNullable<InstalledRulesetStatus["schedulePlanner"]> }) {
  const horizon = formatStatusTime(planner.horizonEnd);
  const refill = formatStatusTime(planner.lastRefill);
  const errorAt = formatStatusTime(planner.lastErrorAt);
  const window = <>Schedules ready until {horizon ?? "—"} (last updated {refill ?? "—"}).</>;
  if (planner.state !== "degraded") {
    return (
      <div role="status" aria-label="Schedule planner" className="text-(--text-muted)">
        Scheduled-rule coverage ready.
        <TechnicalDetails>{window}</TechnicalDetails>
      </div>
    );
  }
  return (
    <div role="status" aria-label="Schedule planner" className={amber}>
      <p className="font-semibold">Schedules need attention.</p>
      <p>Past the scheduled coverage end, a scheduled ALLOW stops matching and a scheduled DENY applies.</p>
      <TechnicalDetails>
        <p>{window}</p>
        {planner.reason && <p>{planner.reason}</p>}
        {planner.lastError && <p>Last update error{errorAt && <> at {errorAt}</>}: {planner.lastError}</p>}
      </TechnicalDetails>
    </div>
  );
}
