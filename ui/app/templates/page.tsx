"use client";

import { useEffect, useState } from "react";

import { api, isAdmin, type Zone } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { Card } from "../../components/Card";

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

type TemplateGeneratedRule = {
  id: string;
  description: string;
  protocol: string;
  functionCodes?: number[];
  addresses?: string[];
  action: string;
  sourceZones?: string[];
  destZones?: string[];
};

type TemplateApplyRequest = {
  template: string;
  sourceZones?: string[];
  destZones?: string[];
  parameters?: Record<string, string>;
};

type TemplateApplyResponse = {
  rules: TemplateGeneratedRule[];
  created?: number;
  updated?: number;
};

/* ── API helpers ───────────────────────────────────────────────── */

async function fetchTemplates(): Promise<ICSTemplate[]> {
  try {
    const res = await fetch("/api/v1/templates/ics", {
      credentials: "include",
      cache: "no-store",
    });
    if (!res.ok) return [];
    return (await res.json()) as ICSTemplate[];
  } catch {
    return [];
  }
}

async function previewTemplate(
  req: TemplateApplyRequest,
): Promise<TemplateApplyResponse | null> {
  try {
    const res = await fetch("/api/v1/templates/ics/apply", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...req, preview: true }),
    });
    if (!res.ok) return null;
    return (await res.json()) as TemplateApplyResponse;
  } catch {
    return null;
  }
}

async function applyTemplate(
  req: TemplateApplyRequest,
): Promise<TemplateApplyResponse | null> {
  try {
    const res = await fetch("/api/v1/templates/ics/apply", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) return null;
    return (await res.json()) as TemplateApplyResponse;
  } catch {
    return null;
  }
}

/* ── Protocol badge colors ─────────────────────────────────────── */

const PROTO_COLORS: Record<string, string> = {
  modbus: "bg-amber-500/[0.2] text-[var(--amber)]",
  dnp3: "bg-purple-500/20 text-purple-300",
  cip: "bg-orange-500/20 text-orange-300",
  s7comm: "bg-teal-500/20 text-teal-300",
  mms: "bg-yellow-500/20 text-yellow-300",
  bacnet: "bg-green-500/20 text-green-300",
  opcua: "bg-pink-500/20 text-pink-300",
};

function protoBadgeClass(proto: string): string {
  return PROTO_COLORS[proto.toLowerCase()] ?? "bg-amber-500/[0.1] text-[var(--text)]";
}

/* ── Page ─────────────────────────────────────────────────────── */

export default function TemplatesPage() {
  const canEdit = isAdmin();
  const [templates, setTemplates] = useState<ICSTemplate[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [activeTemplate, setActiveTemplate] = useState<ICSTemplate | null>(null);

  async function refresh() {
    const [t, z] = await Promise.all([fetchTemplates(), api.listZones()]);
    setTemplates(t);
    setZones(z ?? []);
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <Shell
      title="ICS Rule Templates"
      actions={
        <button
          onClick={refresh}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.1]"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-sm border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {success}
        </div>
      )}

      {/* Description */}
      <Card className="mb-6">
        <div className="text-xs uppercase tracking-[0.2em] text-[var(--text)]">
          About Templates
        </div>
        <p className="mt-2 text-sm text-[var(--text-muted)]">
          ICS rule templates provide pre-built security baselines for common OT
          network configurations. Select a template to generate firewall rules
          tailored to your environment, including Purdue model baselines and
          maintenance window policies.
        </p>
      </Card>

      {/* Template cards */}
      {templates.length === 0 ? (
        <Card>
          <p className="text-sm text-[var(--text-muted)]">
            No templates available. Check that the backend has ICS templates
            configured.
          </p>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {templates.map((t) => (
            <div
              key={t.name}
              className="flex flex-col rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card transition-ui hover:bg-amber-500/[0.08] hover:border-amber-500/30 cursor-pointer"
            >
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-[var(--text)]">{t.name}</h3>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs ${protoBadgeClass(t.protocol)}`}
                >
                  {t.protocol}
                </span>
              </div>
              <p className="mb-4 flex-1 text-xs text-[var(--text-muted)]">
                {t.description}
              </p>
              {t.parameters && t.parameters.length > 0 && (
                <div className="mb-3 text-xs text-[var(--text-muted)]">
                  Parameters:{" "}
                  {t.parameters.map((p) => p.label).join(", ")}
                </div>
              )}
              <button
                onClick={() => setActiveTemplate(t)}
                className="mt-auto rounded-sm bg-[var(--amber)] px-3 py-2 text-sm text-white font-medium transition-ui hover:brightness-110"
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
          zones={zones}
          canEdit={canEdit}
          onClose={() => setActiveTemplate(null)}
          onSuccess={(msg) => {
            setSuccess(msg);
            setActiveTemplate(null);
          }}
          onError={(msg) => setError(msg)}
        />
      )}
    </Shell>
  );
}

/* ── Template Configuration Modal ──────────────────────────────── */

function TemplateModal({
  template,
  zones,
  canEdit,
  onClose,
  onSuccess,
  onError,
}: {
  template: ICSTemplate;
  zones: Zone[];
  canEdit: boolean;
  onClose: () => void;
  onSuccess: (msg: string) => void;
  onError: (msg: string) => void;
}) {
  const [sourceZones, setSourceZones] = useState<string[]>([]);
  const [destZones, setDestZones] = useState<string[]>([]);
  const [params, setParams] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<TemplateGeneratedRule[] | null>(null);
  const [loading, setLoading] = useState(false);

  function buildRequest(): TemplateApplyRequest {
    return {
      template: template.name,
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
    const res = await applyTemplate(buildRequest());
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
    if (parts.length === 0) parts.push(`${res.rules.length} applied`);
    onSuccess(`Template "${template.name}" applied: ${parts.join(", ")}.`);
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
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-[var(--text)]">
              {template.name}
            </h2>
            <p className="text-sm text-[var(--text-muted)]">{template.description}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.1]"
          >
            Close
          </button>
        </div>

        <div className="space-y-4 text-sm">
          {/* Zone selectors */}
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wide text-[var(--text)]">
                Source Zones (optional)
              </label>
              <div className="mt-1 flex flex-wrap gap-1">
                {zones.map((z) => (
                  <button
                    key={z.name}
                    onClick={() =>
                      toggleZone(z.name, sourceZones, setSourceZones)
                    }
                    className={`rounded-full px-2 py-0.5 text-xs ${
                      sourceZones.includes(z.name)
                        ? "bg-amber-500/[0.2] text-[var(--amber)]"
                        : "bg-amber-500/[0.1] text-[var(--text)] hover:bg-amber-500/[0.12]"
                    }`}
                  >
                    {z.name}
                  </button>
                ))}
                {zones.length === 0 && (
                  <span className="text-xs text-[var(--text-muted)]">
                    No zones configured
                  </span>
                )}
              </div>
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-[var(--text)]">
                Destination Zones (optional)
              </label>
              <div className="mt-1 flex flex-wrap gap-1">
                {zones.map((z) => (
                  <button
                    key={z.name}
                    onClick={() => toggleZone(z.name, destZones, setDestZones)}
                    className={`rounded-full px-2 py-0.5 text-xs ${
                      destZones.includes(z.name)
                        ? "bg-amber-500/[0.2] text-[var(--amber)]"
                        : "bg-amber-500/[0.1] text-[var(--text)] hover:bg-amber-500/[0.12]"
                    }`}
                  >
                    {z.name}
                  </button>
                ))}
                {zones.length === 0 && (
                  <span className="text-xs text-[var(--text-muted)]">
                    No zones configured
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Template-specific parameters */}
          {(template.parameters ?? []).map((p) => (
            <div key={p.name}>
              <label className="text-xs uppercase tracking-wide text-[var(--text)]">
                {p.label}
                {p.required && (
                  <span className="ml-1 text-red-400">*</span>
                )}
              </label>
              {p.help && (
                <div className="mt-0.5 text-xs text-[var(--text-muted)]">{p.help}</div>
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
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.1] disabled:opacity-40"
            >
              {loading ? "Loading..." : "Preview"}
            </button>
            {canEdit && (
              <button
                onClick={handleApply}
                disabled={loading}
                className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm text-white font-medium transition-ui hover:brightness-110 disabled:opacity-40"
              >
                Apply
              </button>
            )}
          </div>

          {/* Preview results */}
          {preview && (
            <div className="mt-4">
              <h3 className="mb-2 text-sm font-semibold text-[var(--text)]">
                Preview: {preview.length} Rule(s)
              </h3>
              {preview.length === 0 ? (
                <div className="text-xs text-[var(--text-muted)]">
                  No rules generated with the current parameters.
                </div>
              ) : (
                <div className="overflow-hidden rounded-sm border border-amber-500/[0.15]">
                  <table className="w-full text-sm">
                    <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                        <tr key={r.id} className="border-t border-amber-500/[0.08]">
                          <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                            {r.id}
                          </td>
                          <td className="px-4 py-2 text-[var(--text)]">
                            {r.description || "-"}
                          </td>
                          <td className="px-4 py-2">
                            <span
                              className={`rounded-full px-2 py-0.5 text-xs ${protoBadgeClass(r.protocol)}`}
                            >
                              {r.protocol}
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-xs text-[var(--text)]">
                            {(r.functionCodes ?? []).join(", ") || "*"}
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
