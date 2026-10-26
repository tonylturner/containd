import { notifyConfigMutation } from "./config-events";
import {
  apiURL,
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import {
  deleteJSONResult,
  failureOf,
  getJSON,
  getJSONList,
  parseWarningHeader,
  postJSONResult,
} from "./api-request";

import type { ApiResult } from "./api";

// Packet capture: capture settings, the capture run, and stored captures.

export type PcapForwardTarget = {
  interface?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  proto?: "tcp" | "udp";
};

export type PcapFilter = {
  src?: string;
  dst?: string;
  proto?: "any" | "tcp" | "udp" | "icmp";
  port?: string;
};

export type PcapConfig = {
  enabled?: boolean;
  interfaces?: string[];
  zones?: string[];
  snaplen?: number;
  maxSizeMB?: number;
  maxFiles?: number;
  mode?: "rolling" | "once";
  promisc?: boolean;
  bufferMB?: number;
  rotateSeconds?: number;
  filePrefix?: string;
  filter?: PcapFilter;
  forwardTargets?: PcapForwardTarget[];
};

export type PcapStatus = {
  running: boolean;
  interfaces?: string[];
  startedAt?: string;
  lastError?: string;
};

export type PcapItem = {
  name: string;
  interface: string;
  sizeBytes: number;
  createdAt: string;
  tags?: string[];
  status?: string;
};

export type PcapReplayRequest = {
  name: string;
  interface: string;
  ratePps?: number;
};

export type PcapTagRequest = {
  name: string;
  tags: string[];
};

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

export async function listPcaps(): Promise<PcapItem[]> {
  const res = await getJSONList<PcapItem>("/api/v1/pcap/list");
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
    if (handleUnauthorized(res)) return failureOf(res);
    clearAuthExpired();
    if (!res.ok) return failureOf(res);
    notifyConfigMutation(res);
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
  return apiURL(`/api/v1/pcap/download/${encodeURIComponent(name)}`);
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
