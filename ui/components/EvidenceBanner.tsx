"use client";

import Link from "next/link";
import { useHealth, useHealthSettled } from "../hooks/useHealth";

/** Health exposes only the worst evidence state, never destinations or errors. */
export function EvidenceBanner() {
  const health = useHealth();
  // Before the first poll nothing is known yet; an unavailable health report is "unknown".
  if (!useHealthSettled()) return null;
  const state = health?.evidence?.state ?? "unknown";
  if (state === "ok") return null;
  const failed = state === "degraded";
  return (
    <aside role="status" aria-label="Evidence health"
      className={`mb-4 rounded-xs border px-4 py-3 text-sm ${failed
        ? "border-(--red)/30 bg-(--red)/10 text-(--red)"
        : "border-amber/30 bg-amber/10 text-amber"}`}>
      <p className="mb-1 text-xs font-semibold">Missing activity records</p>
      <p className="font-semibold">{failed ? "Activity records may be missing"
        : state === "recovered" ? "Evidence recovered — history needs review" : "Evidence state unknown"}</p>
      <p className="mt-1 text-xs">
        {failed ? "Saving audit records or sending logs is failing. Operations continue; evidence may be missing."
          : state === "recovered" ? "Saving or sending records is working again. Previous failures and loss are not undone."
            : "Evidence completeness cannot be verified."}{" "}
        Review <Link href="/audit/" className="font-semibold underline">Audit persistence</Link>
        {" and "}<Link href="/system/services/syslog/" className="font-semibold underline">Syslog delivery</Link>.
      </p>
    </aside>
  );
}
