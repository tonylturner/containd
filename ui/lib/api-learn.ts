import type { ApiResult, FirewallRule, PcapIdentification } from "./api";
import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import { failureOf, getJSONResult, postJSONResult } from "./api-request";
import { notifyConfigMutation } from "./config-events";

// Public evidence API projections; rule predicates always use FirewallRule.
export type LearnPage<T> = { items: T[] | null; nextCursor?: string };
export type LearnDataset = {
  schemaVersion: string;
  id: string;
  source: "pcap" | "live";
  state: "importing" | "collecting" | "sealed" | "expired";
  createdAt: string;
  expiresAt: string;
  sealedAt?: string;
  captureSha256?: string;
  decoderVersion: string;
  profileFingerprint: string;
  snapshotFingerprint: string;
  evidenceDigest: string;
  records: number;
  bytes: number;
  gaps: string[] | null;
};
export type LearnWatch = {
  id: string;
  datasetId: string;
  startedAt: string;
  deadline: string;
  stoppedAt?: string;
  stopReason?: string;
};
export type LearnVersions = {
  schema: string;
  observation: string;
  generator: string;
  evaluator: string;
  decoder: string;
  profile: string;
  snapshot: string;
};
export type LearnSelection = { id: string; revision: number };
export type LearnApplyRequest = {
  requestId: string;
  selections: LearnSelection[];
};
export type LearnTotals = { total: number; passed: number; failed: number };
export type LearnSuggestion = LearnSelection & {
  datasetId: string;
  createdAt: string;
  expiresAt: string;
  status:
    | "draft"
    | "certified"
    | "reviewed"
    | "staged"
    | "rejected"
    | "expired";
  content: {
    versions: LearnVersions;
    evidenceDigest: string;
    rules: FirewallRule[];
    limits: string[] | null;
    withheld: string[] | null;
    requiresCoordinateReview: boolean;
  };
  proof?: {
    contentId: string;
    evidenceDigest: string;
    versions: LearnVersions;
    certifiedAt: string;
    positive: LearnTotals;
    negative: LearnTotals;
    parentRefs: { datasetId: string; observationId: string }[] | null;
    counterexamples:
      | {
          mutation: string;
          expected: string;
          actual: string;
          contextDigest: string;
        }[]
      | null;
  };
  review?: {
    actor: string;
    at: string;
    revision: number;
    coordinateApproved: boolean;
  };
  legacyOverlaps: { ruleId: string; reason: string }[] | null;
};
type LearnTuple = {
  source: { ip: string; port: number };
  destination: { ip: string; port: number };
  transport: string;
};
export type LearnObservation = {
  id: string;
  capturedAt: string;
  service: {
    clientIp: string;
    serverIp: string;
    serverPort: number;
    transport: string;
    direction: string;
    protocol: string;
    coordinates: string;
  };
  authority: {
    wire: LearnTuple;
    logical?: LearnTuple;
    correlation: string;
    mappingFingerprint?: string;
    roleCertain: boolean;
    roleEvidence: string;
    standardPort: boolean;
  };
  quality: {
    complete: boolean;
    decoded: boolean;
    conformance: string[] | null;
    undecoded: string[] | null;
    loss: string[] | null;
  };
};
export type LearnCounters = {
  records: number;
  bytes: number;
  evictedRecords: number;
  evictedBytes: number;
  expiredRecords: number;
  lostBatches: number;
  rejectedParents: number;
  withheld: Record<string, number> | null;
};
export type PcapImportResult = {
  dataset: LearnDataset;
  stats: {
    packetCount?: number;
    byteCount?: number;
    duration?: number;
    protocols?: Record<string, number>;
    flows?: unknown[];
    identifications?: PcapIdentification[];
    truncated?: boolean;
    displayTruncated?: boolean;
  };
};
export type LearnGenerateResult = {
  suggestions: LearnSelection[] | null;
  withheld: Record<string, number> | null;
};

const base = "/api/v1/learn";
function query(values: Record<string, string>) {
  return new URLSearchParams({ limit: "200", ...values }).toString();
}
export const learner = {
  datasets: (cursor = "") =>
    getJSONResult<LearnPage<LearnDataset>>(
      `${base}/datasets?${query({ cursor })}`,
    ),
  watches: (cursor = "") =>
    getJSONResult<LearnPage<LearnWatch>>(
      `${base}/watches?${query({ cursor })}`,
    ),
  counters: () => getJSONResult<LearnCounters>(`${base}/counters`),
  suggestions: (datasetId: string, cursor = "") =>
    getJSONResult<LearnPage<LearnSuggestion>>(
      `${base}/suggestions?${query({ datasetId, cursor })}`,
    ),
  observations: (id: string, cursor = "") =>
    getJSONResult<LearnPage<LearnObservation>>(
      `${base}/datasets/${encodeURIComponent(id)}/observations?${query({ cursor })}`,
    ),
  start: (durationSeconds: number) =>
    postJSONResult<LearnWatch>(`${base}/watches`, { durationSeconds }),
  stop: (id: string) =>
    postJSONResult<LearnWatch>(
      `${base}/watches/${encodeURIComponent(id)}/stop`,
      {},
    ),
  generate: (datasetId: string) =>
    postJSONResult<LearnGenerateResult>(`${base}/generate`, { datasetId }),
  review: (
    selection: LearnSelection,
    approve: boolean,
    coordinateApproved: boolean,
  ) =>
    postJSONResult<LearnSuggestion>(
      `${base}/suggestions/${encodeURIComponent(selection.id)}/review`,
      { selection, approve, coordinateApproved },
    ),
  analyze: (name: string) =>
    postJSONResult<PcapImportResult>(
      `/api/v1/pcap/analyze/${encodeURIComponent(name)}`,
      {},
    ),
};

export async function analyzeUpload(
  file: File,
): Promise<ApiResult<PcapImportResult>> {
  try {
    const body = new FormData();
    body.append("file", file, file.name);
    const res = await fetchWithSession("/api/v1/pcap/analyze", {
      method: "POST",
      headers: authHeaders(),
      body,
    });
    if (handleUnauthorized(res)) return failureOf(res);
    clearAuthExpired();
    if (!res.ok) return failureOf(res);
    return { ok: true, data: (await res.json()) as PcapImportResult };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}

// Preserve the status so uncertain persistence can be retried with the same receipt.
export async function stageSuggestions(
  payload: LearnApplyRequest,
): Promise<ApiResult<{ staged: true }> & { status?: number }> {
  try {
    const res = await fetchWithSession(`${base}/apply`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(payload),
    });
    if (handleUnauthorized(res))
      return { ...(await failureOf(res)), status: res.status };
    clearAuthExpired();
    if (!res.ok) return { ...(await failureOf(res)), status: res.status };
    const data = (await res.json()) as { staged: true };
    notifyConfigMutation(res);
    return { ok: true, data, status: res.status };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}

export function selectable(s: LearnSuggestion, now = Date.now()): boolean {
  if (
    !s.proof ||
    s.proof.positive.failed ||
    s.proof.negative.failed ||
    Date.parse(s.expiresAt) <= now
  )
    return false;
  if (s.status !== "certified" && s.status !== "reviewed") return false;
  if (s.content.requiresCoordinateReview && !s.review?.coordinateApproved)
    return false;
  return (
    !s.content.rules.some((r) => r.ics?.protocol === "iec104") ||
    s.status === "reviewed"
  );
}
