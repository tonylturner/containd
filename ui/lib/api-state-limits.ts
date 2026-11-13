import { getJSONShaped, isRecord } from "./api-request";

export type StateLimits = {
  tables: {
    table: string;
    limit: number;
    entries: number;
    chargedBytes: number;
    highWater: number;
    pressure: boolean;
    hits: { reason: string; mode: string; total: number }[];
  }[];
  budget: { limit: number; inUse: number; highWater: number; byCategory: Record<string, number> };
};

export async function fetchStateLimits(signal?: AbortSignal): Promise<StateLimits | null> {
  const data = await getJSONShaped<StateLimits>("/api/v1/diagnostics/state-limits", { lists: ["tables"], objects: ["budget"] }, signal);
  if (!data || data.tables.length === 0 || !(data.budget.limit > 0) ||
    ![data.budget.limit, data.budget.inUse, data.budget.highWater].every(Number.isFinite) ||
    !isRecord(data.budget.byCategory) || !Object.values(data.budget.byCategory).every(Number.isFinite)) return null;
  if (!data.tables.every(row => row && typeof row.table === "string" &&
    [row.limit, row.entries, row.chargedBytes, row.highWater].every(Number.isFinite) &&
    typeof row.pressure === "boolean" && Array.isArray(row.hits) && row.hits.every(hit => hit &&
      typeof hit.reason === "string" && typeof hit.mode === "string" && Number.isFinite(hit.total)))) return null;
  return data;
}
