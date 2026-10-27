import { notifyConfigMutation } from "./config-events";
import {
  apiURL,
  authHeaders,
  clearAuthExpired,
  fetchWithSession,
  handleUnauthorized,
} from "./api-core";
import {
  failureOf,
  getJSON,
  getJSONList,
  postJSON,
  postJSONResult,
} from "./api-request";

import type { ApiResult } from "./api";

// IDS: native rules, rule groups, import and export, Sigma conversion and
// rule sources.

export type IDSCondition = {
  all?: IDSCondition[];
  any?: IDSCondition[];
  not?: IDSCondition;
  field?: string;
  op?: string;
  value?: unknown;
};

export type ContentMatch = {
  pattern: string;
  isHex?: boolean;
  negate?: boolean;
  nocase?: boolean;
  depth?: number;
  offset?: number;
  distance?: number;
  within?: number;
};

export type YARAString = {
  name: string;
  pattern: string;
  type: string; // text|hex|regex
  nocase?: boolean;
  wide?: boolean;
  ascii?: boolean;
};

export type IDSRule = {
  id: string;
  enabled?: boolean | null; // null/undefined = enabled
  title?: string;
  description?: string;
  proto?: string;
  kind?: string;
  when?: IDSCondition;
  severity?: string;
  message?: string;
  labels?: Record<string, string>;
  // Multi-format fields
  sourceFormat?: string;
  action?: string;
  srcAddr?: string;
  dstAddr?: string;
  srcPort?: string;
  dstPort?: string;
  contentMatches?: ContentMatch[];
  yaraStrings?: YARAString[];
  references?: string[];
  cve?: string[];
  mitreAttackIDs?: string[];
  rawSource?: string;
  conversionNotes?: string[];
};

export type RuleGroup = {
  id: string;
  name: string;
  description?: string;
  filter?: string;
  enabled: boolean;
  ruleCount?: number;
};

export type IDSConfig = {
  enabled?: boolean;
  rules?: IDSRule[];
  ruleGroups?: RuleGroup[];
};

export type IDSImportResult = {
  imported: number;
  skipped: number;
  total: number;
  format: string;
};

export type IDSRuleSource = {
  id: string;
  name: string;
  description: string;
  url: string;
  format: string;
  license: string;
  licenseNote?: string;
};

export const idsAPI = {
  getIDS: () => getJSON<IDSConfig>("/api/v1/ids/rules"),
  setIDS: (cfg: IDSConfig) =>
    postJSONResult<IDSConfig>("/api/v1/ids/rules", cfg),
  convertSigma: (sigmaYAML: string) =>
    postJSON<IDSRule>("/api/v1/ids/convert/sigma", { sigmaYAML }),
  importIDSRules: async (
    file: File,
    format?: string,
  ): Promise<ApiResult<IDSImportResult>> => {
    const form = new FormData();
    form.append("file", file);
    if (format) form.append("format", format);
    try {
      const res = await fetchWithSession("/api/v1/ids/import", {
        method: "POST",
        body: form,
        credentials: "include",
        headers: authHeaders(),
      });
      if (handleUnauthorized(res)) return failureOf(res);
      clearAuthExpired();
      if (!res.ok) return failureOf(res);
      notifyConfigMutation(res);
      return { ok: true, data: (await res.json()) as IDSImportResult };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof Error ? e.message : "Network error",
      };
    }
  },
  exportIDSRules: async (format: string): Promise<boolean> => {
    const res = await fetch(
      apiURL(`/api/v1/ids/export?format=${encodeURIComponent(format)}`),
      {
        credentials: "include",
        headers: authHeaders(),
      },
    );
    if (!res.ok) return false;
    const blob = await res.blob();
    const ext: Record<string, string> = {
      suricata: ".rules",
      snort: ".rules",
      yara: ".yar",
      sigma: ".yml",
    };
    const now = new Date();
    const yy = String(now.getFullYear()).slice(2);
    const mm = String(now.getMonth() + 1).padStart(2, "0");
    const dd = String(now.getDate()).padStart(2, "0");
    const filename = `${format}-${yy}${mm}${dd}${ext[format] || ".txt"}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    return true;
  },
  getIDSSources: () => getJSONList<IDSRuleSource>("/api/v1/ids/sources"),
};
