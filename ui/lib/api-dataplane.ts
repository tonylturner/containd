import {
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import {
  deleteJSONResult,
  getJSON,
  parseErrorBody,
  parseWarningHeader,
  postJSONResult,
} from "./api-request";

import type {
  ApiResult,
  DataPlaneConfig,
  PcapConfig,
  PcapItem,
  PcapReplayRequest,
  PcapStatus,
  PcapTagRequest,
  RulesetPreview,
} from "./api";

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

export async function getPcapConfig(): Promise<PcapConfig | null> {
  return await getJSON<PcapConfig>("/api/v1/pcap/config");
}

export async function setPcapConfig(
  cfg: PcapConfig,
): Promise<ApiResult<PcapConfig>> {
  return await postJSONResult<PcapConfig>("/api/v1/pcap/config", cfg);
}

export async function startPcap(
  cfg: PcapConfig,
): Promise<ApiResult<PcapStatus>> {
  return await postJSONResult<PcapStatus>("/api/v1/pcap/start", cfg);
}

export async function stopPcap(): Promise<ApiResult<PcapStatus>> {
  return await postJSONResult<PcapStatus>("/api/v1/pcap/stop", {});
}

export async function getPcapStatus(): Promise<PcapStatus | null> {
  return await getJSON<PcapStatus>("/api/v1/pcap/status");
}

export async function getRulesetPreview(): Promise<RulesetPreview | null> {
  return await getJSON<RulesetPreview>("/api/v1/dataplane/ruleset");
}

export async function listPcaps(): Promise<PcapItem[]> {
  const res = await getJSON<PcapItem[]>("/api/v1/pcap/list");
  return res ?? [];
}

export async function uploadPcap(file: File): Promise<ApiResult<PcapItem>> {
  try {
    const form = new FormData();
    form.append("file", file, file.name);
    const res = await fetchWithSession("/api/v1/pcap/upload", {
      method: "POST",
      headers: authHeaders(),
      body: form,
    });
    if (handleUnauthorized(res)) return { ok: false, error: "Unauthorized" };
    clearAuthExpired();
    if (!res.ok) return { ok: false, error: await parseErrorBody(res) };
    return {
      ok: true,
      data: (await res.json()) as PcapItem,
      warning: parseWarningHeader(res),
    };
  } catch (e) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Network error",
    };
  }
}

export function downloadPcapURL(name: string): string {
  return `/api/v1/pcap/download/${encodeURIComponent(name)}`;
}

export async function deletePcap(name: string): Promise<ApiResult<void>> {
  return await deleteJSONResult(`/api/v1/pcap/${encodeURIComponent(name)}`);
}

export async function tagPcap(
  req: PcapTagRequest,
): Promise<ApiResult<{ status?: string }>> {
  return await postJSONResult<{ status?: string }>("/api/v1/pcap/tag", req);
}

export async function replayPcap(
  req: PcapReplayRequest,
): Promise<ApiResult<{ status?: string }>> {
  return await postJSONResult<{ status?: string }>("/api/v1/pcap/replay", req);
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
