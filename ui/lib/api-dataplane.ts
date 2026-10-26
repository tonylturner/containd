import { authHeaders, fetchWithSession, handleUnauthorized } from "./api-core";
import { getJSONResult, postJSONResult } from "./api-request";
import {
  normalizeICSCoverageReport,
  type ICSCoverageReport,
  type ICSCoverageRule,
} from "./api-ics-coverage";
import type { RuleWarning } from "./api-firewall";

import type { ApiResult, DataPlaneConfig } from "./api";

export type RulesetPreview = {
  ruleset?: string;
  snapshot?: unknown;
  runtime: {
    iec104EnvelopeOpen: boolean;
    reason: string;
  };
  warnings?: RuleWarning[];
  /** Static coverage of the candidate's ICS rules; GET /dataplane/ics-coverage is the UI's source. */
  icsCoverage?: ICSCoverageRule[];
  engineStatus?: RulesetEngineStatus;
  engineStatusError?: string;
};

/** The engine's applied ruleset; icsCoverage includes its runtime faults. */
export type RulesetEngineStatus = {
  ruleset?: string;
  appliedAt?: string;
  error?: string;
  warnings?: RuleWarning[];
  snapshotVersion?: string;
  icsCoverage?: ICSCoverageRule[];
};

export async function fetchDataPlane(): Promise<DataPlaneConfig | null> {
  try {
    const res = await fetchWithSession("/api/v1/dataplane", {
      headers: { ...authHeaders() },
      cache: "no-store",
    });
    if (handleUnauthorized(res) || !res.ok) return null;
    return (await res.json()) as DataPlaneConfig;
  } catch {
    return null;
  }
}

export async function setDataPlane(
  cfg: DataPlaneConfig,
): Promise<ApiResult<DataPlaneConfig>> {
  return await postJSONResult<DataPlaneConfig>("/api/v1/dataplane", cfg);
}

/** Admin-only: the compiled candidate ruleset; 400 when the candidate is invalid. */
export async function getRulesetPreview(): Promise<ApiResult<RulesetPreview>> {
  return await getJSONResult<RulesetPreview>("/api/v1/dataplane/ruleset");
}

/** Candidate and applied ICS coverage for any authenticated user. */
export async function getICSCoverage(): Promise<ApiResult<ICSCoverageReport>> {
  const res = await getJSONResult<unknown>("/api/v1/dataplane/ics-coverage");
  return res.ok ? { ok: true, data: normalizeICSCoverageReport(res.data) } : res;
}

export const dataplaneAPI = {
  blockHostTemp: (ip: string, ttlSeconds?: number) =>
    postJSONResult<{ status: string }>("/api/v1/dataplane/blocks/host", {
      ip,
      ttlSeconds,
    }),
  blockFlowTemp: (req: {
    srcIp: string;
    dstIp: string;
    proto: string;
    dstPort: string;
    ttlSeconds?: number;
  }) =>
    postJSONResult<{ status: string }>("/api/v1/dataplane/blocks/flow", req),
};
