"use client";

import { notifyConfigMutation } from "../../lib/config-events";

import { getJSONList, postJSON } from "../../lib/api-request";
import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useEffect, useRef, useState } from "react";

import { api, apiURL, fetchDataPlane, isAdmin, type Zone, type FirewallRule } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";
import { summarizeGenericICS, formatICSMode, type ICSModeSelection } from "../ics/ics-shared";
import { ICSModeSelect } from "../ics/ics-mode-select";
import { SkeletonList } from "../../components/Skeleton";
import { useConfigForm } from "../../lib/use-config-form";
import { ConfigEditNotice } from "../../lib/use-config-editor";
import { sameConfig } from "../../lib/config-editor";

/* ── Types ─────────────────────────────────────────────────────── */

type ICSTemplate = {
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

type TemplateApplyRequest = {
  template: string;
  mode?: ICSModeSelection;
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
function fetchTemplates(): Promise<ICSTemplate[] | null> {
  return getJSONList<ICSTemplate>("/api/v1/templates/ics");
}

async function previewTemplate(
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

async function applyTemplate(
  req: TemplateApplyRequest,
): Promise<TemplateApplyResponse | null> {
  return postJSON<TemplateApplyResponse>("/api/v1/templates/ics/apply", req);
}

/* ── Protocol badge colors ─────────────────────────────────────── */

const PROTO_COLORS: Record<string, string> = {
  modbus: "text-(--amber)",
  dnp3: "bg-purple-500/20 text-purple-300",
  cip: "bg-orange-500/20 text-orange-300",
  iec104: "bg-cyan-500/20 text-cyan-300",
};

function protoBadgeClass(proto: string): string {
  return PROTO_COLORS[proto.toLowerCase()] ?? "text-(--text)";
}

/* ── Page ─────────────────────────────────────────────────────── */

export default function TemplatesPage() {
  const canEdit = isAdmin();
  const [templates, setTemplates] = useState<ICSTemplate[] | null>([]);
  // Until the first answer the list is unknown, not empty.
  const [loading, setLoading] = useState(true);
  const [globalMode, setGlobalMode] = useState<ICSModeSelection>("");
  const [zones, setZones] = useState<Zone[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [activeTemplate, setActiveTemplate] = useState<ICSTemplate | null>(null);

  async function refresh({ keepEdits = true }: { keepEdits?: boolean } = {}) {
    const [t, z, dp] = await Promise.all([fetchTemplates(), api.listZones(), fetchDataPlane()]);
    setGlobalMode(dp?.dpiMode ?? "");
    setTemplates(t);
    setZones(z ?? []);
    setLoading(false);
    if (!keepEdits) setActiveTemplate(null);
  }

  useConfigRefresh(refresh);

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Shell
      title="ICS Rule Templates"
      actions={
        <button
          onClick={() => refresh({ keepEdits: false })}
          className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-xs border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {success}
        </div>
      )}

      {/* Description */}
      <Card className="mb-6">
        <div className="text-xs uppercase tracking-[0.2em] text-(--text)">
          About Templates
        </div>
        <p className="mt-2 text-sm text-(--text-muted)">
          ICS rule templates provide pre-built security baselines for common OT
          network configurations. Select a template to generate firewall rules
          tailored to your environment, including Purdue model baselines and
          maintenance window policies.
        </p>
        <p className="mt-2 text-xs text-(--text-muted)">
          Maintenance window rules are scheduled ALLOW rules: they admit
          traffic only inside their window, and connections they alone
          admitted stop when it ends.
        </p>
      </Card>

      {/* Template cards */}
      {loading ? (
        <SkeletonList rows={3} />
      ) : templates === null ? (
        <Card>
          <p role="alert" aria-label="Templates unavailable" className="text-sm text-red-400">
            ICS templates unavailable: the server did not return a template list.
          </p>
        </Card>
      ) : templates.length === 0 ? (
        <Card>
          <p className="text-sm text-(--text-muted)">
            No templates available. Check that the backend has ICS templates
            configured.
          </p>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {templates.map((t) => (
            <div
              key={t.name}
              className="flex flex-col rounded-xs border bg-(--surface) p-5 shadow-card transition-ui cursor-pointer"
            >
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-(--text)">{t.name}</h3>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs ${protoBadgeClass(t.protocol)}`}
                >
                  {t.protocol}
                </span>
              </div>
              <p className="mb-4 flex-1 text-xs text-(--text-muted)">
                {t.description}
              </p>
              {t.parameters && t.parameters.length > 0 && (
                <div className="mb-3 text-xs text-(--text-muted)">
                  Parameters:{" "}
                  {t.parameters.map((p) => p.label).join(", ")}
                </div>
              )}
              <button
                onClick={() => setActiveTemplate(t)}
                className="mt-auto rounded-xs bg-(--amber) px-3 py-2 text-sm text-white font-medium transition-ui hover:brightness-110"
              >
                Generate Rules
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Template configuration modal */}
      {activeTemplate && (
        <TemplateModal
          template={activeTemplate}
          globalMode={globalMode}
          context={templates}
          zones={zones}
          canEdit={canEdit}
          onClose={() => setActiveTemplate(null)}
          onSuccess={(msg, close) => {
            setSuccess(msg);
            if (close) setActiveTemplate(null);
          }}
          onError={(msg) => setError(msg)}
        />
      )}
    </Shell>
  );
}

/* ── Template Configuration Modal ──────────────────────────────── */

function TemplateModal({
  context,
  globalMode,
  template,
  zones,
  canEdit,
  onClose,
  onSuccess,
  onError,
}: {
  context: ICSTemplate[] | null;
  globalMode: ICSModeSelection;
  template: ICSTemplate;
  zones: Zone[];
  canEdit: boolean;
  onClose: () => void;
  onSuccess: (msg: string, close: boolean) => void;
  onError: (msg: string) => void;
}) {
  const form = useConfigForm({ sourceZones: [] as string[], destZones: [] as string[], params: {} as Record<string, string>, mode: "" as ICSModeSelection });
  const { refreshForm } = form;
  useEffect(() => { refreshForm({ templates: context, zones, globalMode }); }, [refreshForm, context, zones, globalMode]);
  const [sourceZones, setSourceZones] = form.field("sourceZones");
  const [destZones, setDestZones] = form.field("destZones");
  const [mode, setMode] = form.field("mode");
  const [params, setParams] = form.field("params");
  const latest = useRef(form.editor);
  latest.current = form.editor;
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [preview, setPreview] = useState<FirewallRule[] | null>(null);
  const [loading, setLoading] = useState(false);

  function buildRequest(): TemplateApplyRequest {
    return {
      template: template.name,
      mode,
      sourceZones: sourceZones.length > 0 ? sourceZones : undefined,
      destZones: destZones.length > 0 ? destZones : undefined,
      parameters: Object.keys(params).length > 0 ? params : undefined,
    };
  }

  async function handlePreview() {
    setLoading(true);
    const res = await previewTemplate(buildRequest());
    setLoading(false);
    if (!res) {
      onError("Failed to preview template rules.");
      return;
    }
    setPreview(res.rules);
  }

  async function handleApply() {
    if (!canEdit) return;
    setLoading(true);
    const submitted = form.editor;
    const res = await applyTemplate(buildRequest());
    if (!mounted.current) return;
    setLoading(false);
    if (!res) {
      onError("Failed to apply template.");
      return;
    }
    const created = res.created ?? res.rules.length;
    const updated = res.updated ?? 0;
    const parts = [];
    if (created > 0) parts.push(`${created} created`);
    if (updated > 0) parts.push(`${updated} updated`);
    if (parts.length === 0) parts.push(`${res.rules.length} rules`);
    form.acceptFields(submitted, ["sourceZones", "destZones", "params", "mode"]);
    onSuccess(`Template "${template.name}" staged — commit to apply. ${parts.join(", ")}.`,
      sameConfig(latest.current.cfg.fields, submitted.cfg.fields));
  }

  function toggleZone(
    zone: string,
    current: string[],
    setter: (v: string[]) => void,
  ) {
    if (current.includes(zone)) {
      setter(current.filter((z) => z !== zone));
    } else {
      setter([...current, zone]);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xs border bg-(--surface) p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-(--text)">
              {template.name}
            </h2>
            <p className="text-sm text-(--text-muted)">{template.description}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui"
          >
            Close
          </button>
        </div>

        <ConfigEditNotice superseded={form.editor.superseded} />
        <div className="space-y-4 text-sm">
          {/* Zone selectors */}
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wide text-(--text)">
                Source Zones (optional)
              </label>
              <div className="mt-1 flex flex-wrap gap-1">
                {Array.from(new Set([...zones.map((z) => z.name), ...sourceZones])).map((name) => (
                  <button
                    key={name}
                    onClick={() =>
                      toggleZone(name, sourceZones, setSourceZones)
                    }
                    className={`rounded-full px-2 py-0.5 text-xs ${
                      sourceZones.includes(name)
                        ? "text-(--amber)"
                        : "text-(--text) "
                    }`}
                  >
                    {name}{!zones.some((zone) => zone.name === name) && " (no longer on server)"}
                  </button>
                ))}
                {zones.length === 0 && (
                  <span className="text-xs text-(--text-muted)">
                    No zones configured
                  </span>
                )}
              </div>
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-(--text)">
                Destination Zones (optional)
              </label>
              <div className="mt-1 flex flex-wrap gap-1">
                {Array.from(new Set([...zones.map((z) => z.name), ...destZones])).map((name) => (
                  <button
                    key={name}
                    onClick={() => toggleZone(name, destZones, setDestZones)}
                    className={`rounded-full px-2 py-0.5 text-xs ${
                      destZones.includes(name)
                        ? "text-(--amber)"
                        : "text-(--text) "
                    }`}
                  >
                    {name}{!zones.some((zone) => zone.name === name) && " (no longer on server)"}
                  </button>
                ))}
                {zones.length === 0 && (
                  <span className="text-xs text-(--text-muted)">
                    No zones configured
                  </span>
                )}
              </div>
            </div>
          </div>

          {template.protocol && <ICSModeSelect value={mode} onChange={setMode} globalMode={globalMode} />}
          <p className="text-xs text-(--text-muted)">Mode applies only to generated ICS rules. Monitor rules never admit traffic; other firewall rules and defaults still apply.</p>
          {/* Template-specific parameters */}
          {(template.parameters ?? []).map((p) => (
            <div key={p.name}>
              <label className="text-xs uppercase tracking-wide text-(--text)">
                {p.label}
                {p.required && (
                  <span className="ml-1 text-red-400">*</span>
                )}
              </label>
              {p.help && (
                <div className="mt-0.5 text-xs text-(--text-muted)">{p.help}</div>
              )}
              <input
                value={params[p.name] ?? ""}
                onChange={(e) =>
                  setParams((prev) => ({ ...prev, [p.name]: e.target.value }))
                }
                placeholder={p.placeholder ?? ""}
                className="mt-1 w-full input-industrial"
              />
            </div>
          ))}

          {/* Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={handlePreview}
              disabled={loading}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-40"
            >
              {loading ? "Loading..." : "Preview"}
            </button>
            {canEdit && (
              <button
                onClick={handleApply}
                disabled={loading}
                className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm text-white font-medium transition-ui hover:brightness-110 disabled:opacity-40"
              >
                Stage
              </button>
            )}
          </div>

          {/* Preview results */}
          {preview && (
            <div className="mt-4">
              <h3 className="mb-2 text-sm font-semibold text-(--text)">
                Preview: {preview.length} Rule(s)
              </h3>
              {preview.length === 0 ? (
                <div className="text-xs text-(--text-muted)">
                  No rules generated with the current parameters.
                </div>
              ) : (
                <div className="overflow-hidden rounded-xs border">
                  <table className="w-full text-sm">
                    <thead className="bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
                      <tr>
                        <th className="px-4 py-2">ID</th>
                        <th className="px-4 py-2">Description</th>
                        <th className="px-4 py-2">Protocol</th>
                        <th className="px-4 py-2">Function Codes</th>
                        <th className="px-4 py-2">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.map((r) => (
                        <tr key={r.id} className="border-t">
                          <td className="px-4 py-2 font-mono text-xs text-(--text)">
                            {r.id}
                          </td>
                          <td className="px-4 py-2 text-(--text)">
                            {r.description || "-"}
                          </td>
                          <td className="px-4 py-2">
                            <span
                              className={`rounded-full px-2 py-0.5 text-xs ${protoBadgeClass(r.ics?.protocol ?? "")}`}
                            >
                              {r.ics?.protocol || "-"}
                              {r.ics?.protocol && <span className="block">{formatICSMode(r.ics.mode, globalMode).label}</span>}
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-xs text-(--text)">
                            {(r.ics?.functionCode ?? []).join(", ") || "*"}
                            {r.ics && <div className="mt-1 text-(--text-muted)">{summarizeGenericICS(r.ics, false)}</div>}
                          </td>
                          <td className="px-4 py-2">
                            <span
                              className={`rounded-full px-2 py-0.5 text-xs ${
                                r.action === "ALLOW"
                                  ? "bg-emerald-500/20 text-emerald-400"
                                  : "bg-red-500/20 text-red-400"
                              }`}
                            >
                              {r.action}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
