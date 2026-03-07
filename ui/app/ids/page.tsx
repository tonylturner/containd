"use client";

import { useEffect, useMemo, useState } from "react";

import { Shell } from "../../components/Shell";
import { api, isAdmin, type IDSConfig, type IDSRule } from "../../lib/api";

export default function IDSPage() {
  const canEdit = isAdmin();
  const [ids, setIds] = useState<IDSConfig>({ enabled: false, rules: [] });
  const [sigmaText, setSigmaText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<IDSRule | null>(null);

  async function refresh() {
    const cfg = await api.getIDS();
    setIds(cfg ?? { enabled: false, rules: [] });
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    const saved = await api.setIDS(ids);
    if (!saved) {
      setError("Failed to save IDS rules.");
      return;
    }
    setIds(saved);
  }

  async function onConvertSigma() {
    if (!canEdit) return;
    setError(null);
    const rule = await api.convertSigma(sigmaText);
    if (!rule) {
      setError("Sigma conversion failed. Check YAML.");
      return;
    }
    const existing = ids.rules ?? [];
    if (existing.some((r) => r.id === rule.id)) {
      setError(`Rule id ${rule.id} already exists.`);
      return;
    }
    setIds({ ...ids, rules: [...existing, rule] });
  }

  function onDelete(id: string) {
    if (!canEdit) return;
    const existing = ids.rules ?? [];
    setIds({ ...ids, rules: existing.filter((r) => r.id !== id) });
  }

  const rules = useMemo(() => ids.rules ?? [], [ids.rules]);

  return (
    <Shell
      title="IDS Rules"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
            >
              Save
            </button>
          )}
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="mb-6 flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-slate-200">
          <input
            type="checkbox"
            checked={!!ids.enabled}
            disabled={!canEdit}
            onChange={(e) => setIds({ ...ids, enabled: e.target.checked })}
            className="h-4 w-4 rounded border-white/20 bg-black/40"
          />
          Enable native IDS
        </label>
      </div>

      {canEdit && (
        <SigmaImportCard
          value={sigmaText}
          onChange={setSigmaText}
          onConvert={onConvertSigma}
        />
      )}

      <div className="mt-6 overflow-hidden rounded-2xl border border-white/10 bg-white/5 shadow-lg backdrop-blur">
        <table className="w-full text-sm">
          <thead className="bg-black/30 text-left text-xs uppercase tracking-wide text-slate-300">
            <tr>
              <th className="px-4 py-3">ID</th>
              <th className="px-4 py-3">Title</th>
              <th className="px-4 py-3">Proto/Kind</th>
              <th className="px-4 py-3">When</th>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td className="px-4 py-4 text-slate-400" colSpan={6}>
                  No IDS rules configured. Upload Suricata rules or create custom rules to enable intrusion detection.
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id} className="border-t border-white/5">
                <td className="px-4 py-3 font-mono text-xs text-white">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {r.title || r.message || "—"}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  {(r.proto || "*") + " / " + (r.kind || "*")}
                </td>
                <td className="px-4 py-3 text-slate-200">
                  <span title={conditionSummary(r.when)}>
                    {conditionSummary(r.when) || "—"}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-200">
                  <span
                    className={
                      r.severity === "critical" || r.severity === "high"
                        ? "rounded-full bg-amber/20 px-2 py-0.5 text-xs text-amber"
                        : r.severity === "medium"
                          ? "rounded-full bg-white/10 px-2 py-0.5 text-xs text-slate-200"
                          : "rounded-full bg-mint/20 px-2 py-0.5 text-xs text-mint"
                    }
                  >
                    {r.severity || "low"}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  {canEdit && (
                    <>
                      <button
                        onClick={() => setEditing(r)}
                        className="mr-2 rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => onDelete(r.id)}
                        className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30"
                      >
                        Remove
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {editing && canEdit && (
        <EditRuleModal
          rule={editing}
          onClose={() => setEditing(null)}
          onSave={(newRule) => {
            const existing = ids.rules ?? [];
            setIds({
              ...ids,
              rules: existing.map((r) => (r.id === editing.id ? newRule : r)),
            });
            setEditing(null);
          }}
        />
      )}
    </Shell>
  );
}

function conditionSummary(when: IDSRule["when"]): string {
  if (!when) return "";
  if (when.field) {
    const v =
      typeof when.value === "string"
        ? when.value
        : Array.isArray(when.value)
          ? when.value.join(",")
          : when.value !== undefined
            ? String(when.value)
            : "";
    return `${when.field} ${when.op || "equals"} ${v}`.trim();
  }
  if (when.all?.length) return `all(${when.all.length})`;
  if (when.any?.length) return `any(${when.any.length})`;
  if (when.not) return `not(${conditionSummary(when.not)})`;
  return "";
}

function SigmaImportCard({
  value,
  onChange,
  onConvert,
}: {
  value: string;
  onChange: (v: string) => void;
  onConvert: () => void;
}) {
  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    onChange(text);
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-4 shadow-lg">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white">Import Sigma Rule</h2>
        <input
          type="file"
          accept=".yml,.yaml,text/yaml"
          onChange={onFile}
          className="text-xs text-slate-300"
        />
      </div>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste Sigma YAML here"
        rows={8}
        className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white"
      />
      <div className="mt-2 flex justify-end">
        <button
          onClick={onConvert}
          disabled={!value.trim()}
          className="rounded-lg bg-white/10 px-3 py-1.5 text-sm text-white hover:bg-white/20 disabled:opacity-50"
        >
          Convert & Add
        </button>
      </div>
    </div>
  );
}

function EditRuleModal({
  rule,
  onClose,
  onSave,
}: {
  rule: IDSRule;
  onClose: () => void;
  onSave: (r: IDSRule) => void;
}) {
  const [text, setText] = useState(JSON.stringify(rule, null, 2));
  const [err, setErr] = useState<string | null>(null);

  function save() {
    setErr(null);
    try {
      const parsed = JSON.parse(text) as IDSRule;
      if (!parsed.id) {
        setErr("Rule must have an id.");
        return;
      }
      onSave(parsed);
    } catch (e) {
      setErr("Invalid JSON.");
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-3xl rounded-2xl border border-white/10 bg-ink p-5 shadow-2xl">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">
            Edit IDS rule {rule.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md bg-white/5 px-2 py-1 text-xs hover:bg-white/10"
          >
            Close
          </button>
        </div>
        {err && (
          <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
            {err}
          </div>
        )}
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={14}
          className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 font-mono text-xs text-white"
        />
        <div className="mt-3 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-lg bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
          >
            Save rule
          </button>
        </div>
      </div>
    </div>
  );
}
