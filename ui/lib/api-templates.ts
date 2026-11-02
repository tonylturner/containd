import { apiURL, type FirewallRule } from "./api";
import { getJSONList, postJSONResult } from "./api-request";
import { notifyConfigMutation } from "./config-events";

/* ── Types ─────────────────────────────────────────────────────── */

export type ICSTemplate = {
  name: string;
  description: string;
  protocol: string;
  parameters?: TemplateParameter[];
};

type TemplateParameter = {
  name: string;
  label: string;
  type: "text" | "number" | "select";
  required?: boolean;
  placeholder?: string;
  help?: string;
};

export type TemplateApplyRequest = {
  template: string;
  mode?: "enforce" | "monitor" | "";
  sourceZones?: string[];
  destZones?: string[];
  parameters?: Record<string, string>;
};

type TemplateApplyResponse = {
  rules: FirewallRule[];
  created?: number;
  updated?: number;
};

/* ── API helpers ───────────────────────────────────────────────── */

/** The ICS templates; null when unavailable or not a list. */
export function fetchTemplates(): Promise<ICSTemplate[] | null> {
  return getJSONList<ICSTemplate>("/api/v1/templates/ics");
}

export async function previewTemplate(
  req: TemplateApplyRequest,
): Promise<TemplateApplyResponse | null> {
  try {
    const res = await fetch(apiURL("/api/v1/templates/ics/apply"), {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...req, preview: true }),
    });
    if (!res.ok) return null;
    notifyConfigMutation(res);
    return (await res.json()) as TemplateApplyResponse;
  } catch {
    return null;
  }
}

export async function applyTemplate(
  req: TemplateApplyRequest,
  revision: string,
) {
  return postJSONResult<TemplateApplyResponse>("/api/v1/templates/ics/apply", req, revision);
}
