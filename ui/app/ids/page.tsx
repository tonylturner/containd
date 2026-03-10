"use client";

import { useEffect, useMemo, useState } from "react";

import { Shell } from "../../components/Shell";
import { api, isAdmin, type IDSConfig, type IDSRule } from "../../lib/api";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";
import {
  ConfirmDialog,
  useConfirm,
} from "../../components/ConfirmDialog";

export default function IDSPage() {
  const canEdit = isAdmin();
  const [ids, setIds] = useState<IDSConfig>({ enabled: false, rules: [] });
  const [sigmaText, setSigmaText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<IDSRule | null>(null);
  const confirm = useConfirm();

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
    confirm.open({
      title: "Remove IDS Rule",
      message: `Are you sure you want to remove rule "${id}"? This change is not saved until you click Save.`,
      confirmLabel: "Remove",
      variant: "danger",
      onConfirm: () => {
        const existing = ids.rules ?? [];
        setIds({ ...ids, rules: existing.filter((r) => r.id !== id) });
      },
    });
  }

  const rules = useMemo(() => ids.rules ?? [], [ids.rules]);

  return (
    <Shell
      title="IDS Rules"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Save
            </button>
          )}
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="mb-6 flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm text-[var(--text)]">
          <input
            type="checkbox"
            checked={!!ids.enabled}
            disabled={!canEdit}
            onChange={(e) => setIds({ ...ids, enabled: e.target.checked })}
            className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
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

      <div className="mt-6 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] shadow-card">
        <table className="w-full text-sm">
          <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
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
                <td className="px-4 py-8" colSpan={6}>
                  <EmptyState
                    title="No IDS rules configured"
                    description="Upload Suricata rules or create custom rules to enable intrusion detection."
                  />
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <tr key={r.id} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                <td className="px-4 py-3 font-mono text-xs text-[var(--text)]">
                  {r.id}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {r.title || r.message || "\u2014"}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  {(r.proto || "*") + " / " + (r.kind || "*")}
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  <span title={conditionSummary(r.when)}>
                    {conditionSummary(r.when) || "\u2014"}
                  </span>
                </td>
                <td className="px-4 py-3 text-[var(--text)]">
                  <StatusBadge
                    variant={
                      r.severity === "critical" || r.severity === "high"
                        ? "error"
                        : r.severity === "medium"
                          ? "warning"
                          : "success"
                    }
                  >
                    {r.severity || "low"}
                  </StatusBadge>
                </td>
                <td className="px-4 py-3 text-right">
                  {canEdit && (
                    <>
                      <button
                        onClick={() => setEditing(r)}
                        className="mr-2 rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => onDelete(r.id)}
                        className="rounded-md px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
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

      <ConfirmDialog {...confirm.props} />
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
    <Card title="Import Sigma Rule" titleRight={
      <input
        type="file"
        accept=".yml,.yaml,text/yaml"
        onChange={onFile}
        className="text-xs text-[var(--text)]"
      />
    }>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste Sigma YAML here"
        rows={8}
        className="w-full input-industrial font-mono text-xs"
      />
      <div className="mt-2 flex justify-end">
        <button
          onClick={onConvert}
          disabled={!value.trim()}
          className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
        >
          Convert & Add
        </button>
      </div>
    </Card>
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4 animate-fade-in">
      <div className="w-full max-w-3xl rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card-lg animate-fade-in">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-[var(--text)]">
            Edit IDS rule {rule.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs transition-ui hover:bg-amber-500/[0.08]"
          >
            Close
          </button>
        </div>
        {err && (
          <div className="mb-3 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            {err}
          </div>
        )}
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={14}
          className="w-full input-industrial font-mono text-xs"
        />
        <div className="mt-3 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
          >
            Save rule
          </button>
        </div>
      </div>
    </div>
  );
}
