"use client";

import { useMemo, useRef, useState } from "react";

import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { api, type IDSRule, type IDSRuleSource, type RuleGroup } from "../../lib/api";

import {
  EXPORT_FORMATS,
  FORMAT_OPTIONS,
  FormatBadge,
  groupFilterMatch,
} from "./ids-shared";

export function GroupsPanel({
  groups,
  rules,
  canEdit,
  onUpdate,
}: {
  groups: RuleGroup[];
  rules: IDSRule[];
  canEdit: boolean;
  onUpdate: (g: RuleGroup[]) => void;
}) {
  const [name, setName] = useState("");
  const [filter, setFilter] = useState("");

  const groupStats = useMemo(() => {
    const stats: Record<string, number> = {};
    for (const g of groups) {
      if (!g.filter) {
        stats[g.id] = rules.length;
        continue;
      }
      stats[g.id] = rules.filter((r) => groupFilterMatch(r, g.filter ?? "")).length;
    }
    return stats;
  }, [groups, rules]);

  function onCreate() {
    if (!name.trim()) {
      return;
    }
    const id = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-");
    if (groups.some((g) => g.id === id)) {
      return;
    }
    onUpdate([
      ...groups,
      { id, name: name.trim(), filter: filter.trim(), enabled: true },
    ]);
    setName("");
    setFilter("");
  }

  function onToggle(id: string) {
    onUpdate(groups.map((g) => (g.id === id ? { ...g, enabled: !g.enabled } : g)));
  }

  function onRemove(id: string) {
    onUpdate(groups.filter((g) => g.id !== id));
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-(--text-muted)">
        Organize rules into groups by protocol, vendor, or use case. Groups use
        filter expressions to match rules (e.g.{" "}
        <code>proto:modbus</code>,{" "}
        <code>format:suricata</code>,{" "}
        <code>severity:critical</code>).
      </p>

      {canEdit && (
        <Card title="Create group">
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[150px] flex-1">
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-(--text-dim)">
                Name
              </label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. ICS/Modbus"
                className="input-industrial w-full text-sm"
              />
            </div>
            <div className="min-w-[200px] flex-1">
              <label className="mb-1 block text-[10px] uppercase tracking-wider text-(--text-dim)">
                Filter
              </label>
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="proto:modbus"
                className="input-industrial w-full font-mono text-sm"
              />
            </div>
            <button
              onClick={onCreate}
              disabled={!name.trim()}
              className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
            >
              Create
            </button>
          </div>
        </Card>
      )}

      {groups.length === 0 ? (
        <EmptyState
          title="No rule groups"
          description="Create groups to organize large rule sets by protocol or vendor."
        />
      ) : (
        <div className="space-y-2">
          {groups.map((g) => (
            <div
              key={g.id}
              className={`flex items-center gap-3 rounded-xs border p-3 transition-ui ${
                g.enabled
                  ? "bg-(--surface)"
                  : "border-white/5 bg-(--surface) opacity-60"
              }`}
            >
              {canEdit && (
                <button
                  onClick={() => onToggle(g.id)}
                  title={g.enabled ? "Disable group" : "Enable group"}
                  className={`inline-flex h-5 w-9 items-center rounded-full transition-colors ${g.enabled ? "bg-emerald-500/30" : "bg-white/10"}`}
                >
                  <span
                    className={`inline-block h-3.5 w-3.5 rounded-full transition-transform ${g.enabled ? "translate-x-[18px] bg-emerald-400" : "translate-x-[3px] bg-white/30"}`}
                  />
                </button>
              )}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-(--text)">
                    {g.name}
                  </span>
                  {g.filter && (
                    <code className="truncate font-mono text-[10px]">
                      {g.filter}
                    </code>
                  )}
                </div>
                {g.description && (
                  <p className="mt-0.5 text-xs text-(--text-muted)">
                    {g.description}
                  </p>
                )}
              </div>
              <span className="shrink-0 tabular-nums text-xs text-(--text-muted)">
                {(groupStats[g.id] ?? 0).toLocaleString()} rules
              </span>
              {canEdit && (
                <button
                  onClick={() => onRemove(g.id)}
                  className="text-xs text-red-400 transition-ui hover:text-red-300"
                >
                  Del
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function ImportPanel({
  onImported,
  onError,
}: {
  onImported: (msg: string) => void;
  onError: (msg: string) => void;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [format, setFormat] = useState("");
  const [importing, setImporting] = useState(false);
  const [sigmaText, setSigmaText] = useState("");
  const [sigmaConverting, setSigmaConverting] = useState(false);

  async function onFileImport() {
    const file = fileRef.current?.files?.[0];
    if (!file) {
      return;
    }
    setImporting(true);
    onError("");
    const result = await api.importIDSRules(file, format || undefined);
    setImporting(false);
    if (!result.ok) {
      onError(result.error || "Import failed. Check the file format and try again.");
      return;
    }
    onImported(
      `IDS rules staged — commit to apply. Imported ${result.data.imported} rule${result.data.imported !== 1 ? "s" : ""} (${result.data.skipped} skipped). Format: ${result.data.format}. Total: ${result.data.total}.`,
    );
    if (fileRef.current) {
      fileRef.current.value = "";
    }
  }

  async function onSigmaConvert() {
    if (!sigmaText.trim()) {
      return;
    }
    setSigmaConverting(true);
    onError("");
    const rule = await api.convertSigma(sigmaText);
    setSigmaConverting(false);
    if (!rule) {
      onError("Sigma conversion failed. Check YAML syntax.");
      return;
    }
    onImported(`Converted Sigma rule: ${rule.id}. Click Save to persist.`);
    setSigmaText("");
  }

  return (
    <div className="space-y-4">
      <Card title="Import from file">
        <p className="mb-3 text-xs text-(--text-muted)">
          Upload Suricata (.rules), Snort (.rules), YARA (.yar), or Sigma
          (.yml). Format is auto-detected.
        </p>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[200px] flex-1">
            <label className="mb-1 block text-xs text-(--text-muted)">
              Rule file
            </label>
            <input
              ref={fileRef}
              type="file"
              accept=".rules,.yar,.yara,.yml,.yaml"
              className="w-full text-sm text-(--text) file:mr-3 file:rounded-xs file:border file:bg-(--surface2) file:px-3 file:py-1.5 file:text-xs file:text-(--text) file:transition-ui"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-(--text-muted)">
              Format
            </label>
            <select
              value={format}
              onChange={(e) => setFormat(e.target.value)}
              className="input-industrial text-sm"
            >
              {FORMAT_OPTIONS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={onFileImport}
            disabled={importing}
            className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
          >
            {importing ? "Importing..." : "Import"}
          </button>
        </div>
      </Card>
      <Card title="Paste Sigma YAML">
        <textarea
          value={sigmaText}
          onChange={(e) => setSigmaText(e.target.value)}
          placeholder="Paste a single Sigma YAML rule here..."
          rows={8}
          className="input-industrial w-full font-mono text-xs"
        />
        <div className="mt-2 flex justify-end">
          <button
            onClick={onSigmaConvert}
            disabled={!sigmaText.trim() || sigmaConverting}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
          >
            {sigmaConverting ? "Converting..." : "Convert & Add"}
          </button>
        </div>
      </Card>
    </div>
  );
}

export function ExportPanel({ ruleCount }: { ruleCount: number }) {
  const [exporting, setExporting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refusedCount, setRefusedCount] = useState<number | null>(null);

  async function doExport(format: string) {
    setExporting(format);
    setError(null);
    setRefusedCount(null);
    const result = await api.exportIDSRules(format);
    setExporting(null);
    if (!result.ok) {
      setError(result.error || `Export failed for ${format}.`);
    } else {
      setRefusedCount(result.data.refusedCount);
    }
  }

  return (
    <Card title="Export rules">
      <p className="mb-4 text-xs text-(--text-muted)">
        Download running rules in your chosen format. Snort and Suricata refuse
        rules they cannot preserve; the file lists each refusal. Unsaved and
        staged changes are not included.
      </p>
      {refusedCount !== null && (
        <p role="status" aria-label="Export result" className="mb-3 text-sm text-(--text)">
          Downloaded. {refusedCount} rule{refusedCount !== 1 ? "s" : ""} refused.
          {refusedCount > 0 && " Review the refusal comments in the downloaded file."}
        </p>
      )}
      {error && (
        <div className="mb-3 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          {error}
        </div>
      )}
      {ruleCount === 0 && (
        <p className="mb-3 text-sm text-(--text-muted)">
          No candidate rules. Running rules can still be exported.
        </p>
      )}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {EXPORT_FORMATS.map((f) => (
          <button
            key={f.value}
            onClick={() => doExport(f.value)}
            disabled={exporting !== null}
            className="flex flex-col items-center gap-2 rounded-xs border bg-(--surface2) p-4 text-center transition-ui disabled:opacity-50"
          >
            <FormatBadge format={f.value} />
            <span className="text-sm text-(--text)">{f.label}</span>
            <span className="text-[10px] text-(--text-muted)">
              {exporting === f.value ? "Downloading..." : "Download"}
            </span>
          </button>
        ))}
      </div>
    </Card>
  );
}

export function SourcesCatalog({ sources }: { sources: IDSRuleSource[] }) {
  return (
    <div className="space-y-3">
      <p className="text-xs text-(--text-muted)">
        Community rule repositories. Download externally, then import via the
        Import tab. GPL sets are not shipped.
      </p>
      {sources.length === 0 ? (
        <EmptyState title="No rule sources" description="Catalog is empty." />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {sources.map((s) => (
            <div
              key={s.id}
              className="rounded-xs border bg-(--surface2) p-4 transition-ui"
            >
              <div className="mb-2 flex items-start justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-(--text)">
                    {s.name}
                  </h3>
                  <p className="mt-0.5 text-xs text-(--text-muted)">
                    {s.description}
                  </p>
                </div>
                <FormatBadge format={s.format} />
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span
                  className={`rounded-xs border px-1.5 py-0.5 ${
                    s.license === "MIT" || s.license === "CC0-1.0"
                      ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                      : s.license.startsWith("GPL")
                        ? "border-orange-500/20 bg-orange-500/10 text-orange-400"
                        : "border-blue-500/20 bg-blue-500/10 text-blue-400"
                  }`}
                >
                  {s.license}
                </span>
                <a
                  href={s.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="truncate transition-ui"
                >
                  {s.url.replace(/^https?:\/\//, "").split("/").slice(0, 3).join("/")}
                </a>
              </div>
              {s.licenseNote && (
                <p className="mt-2 text-[10px] text-orange-400/80">
                  {s.licenseNote}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function EditRuleModal({
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
    } catch {
      setErr("Invalid JSON.");
    }
  }

  return (
    <div className="animate-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="animate-fade-in w-full max-w-3xl rounded-xs border bg-(--surface) p-5 shadow-card-lg">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-(--text)">
            Edit: {rule.id}
          </h2>
          <button
            onClick={onClose}
            className="rounded-md border bg-(--surface2) px-2 py-1 text-xs transition-ui"
          >
            Close
          </button>
        </div>
        {err && (
          <div className="mb-3 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
            {err}
          </div>
        )}
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={16}
          className="input-industrial w-full font-mono text-xs"
        />
        <div className="mt-3 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            onClick={save}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
          >
            Save rule
          </button>
        </div>
      </div>
    </div>
  );
}
