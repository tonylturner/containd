import type { AuditPersistenceStatus } from "../lib/api-evidence";
import { formatTimestamp } from "../lib/utils";
import { TechnicalDetails } from "./TechnicalDetails";

export function EvidenceBannerAudit({ audit, loading }: { audit: AuditPersistenceStatus | null; loading: boolean }) {
  const state = audit?.state ?? "unknown";
  return (
    <section aria-label="Audit persistence" className={`mb-4 rounded-xs border p-4 text-sm ${
      state === "degraded" ? "border-(--red)/30 bg-(--red)/10 text-(--red)"
        : state !== "ok" ? "border-amber/30 bg-amber/10 text-amber" : "bg-(--surface) text-(--text)"}`}>
      <h2 className="font-semibold">Audit persistence: {loading ? "checking" : state}</h2>
      <p className="mt-1 text-xs">Local audit storage, not remote log delivery. Operations continue even when saving audit records fails.</p>
      {audit && !loading && (
        <div className="mt-2 space-y-1 text-xs">
          <p>Failed saves since service restart: {audit.failures}</p>
          <p>Last failure: {audit.lastFailureAt ? formatTimestamp(audit.lastFailureAt) : "—"}</p>
          <p>Last success: {audit.lastSuccessAt ? formatTimestamp(audit.lastSuccessAt) : "—"}</p>
          {audit.lastError && <TechnicalDetails>Last error: {audit.lastError}</TechnicalDetails>}
          {state === "recovered" && <p>Writes have resumed; previously missing records are not restored.</p>}
        </div>
      )}
      {!loading && state === "unknown" && <p className="mt-2 text-xs">Persistence could not be verified. Do not treat an empty audit log as proof that no actions occurred.</p>}
    </section>
  );
}
