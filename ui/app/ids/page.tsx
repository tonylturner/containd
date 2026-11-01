"use client";

import { revisionError, useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../lib/use-config-editor";
import { upsertRow } from "../../lib/config-editor";
import { useConfigForm } from "../../lib/use-config-form";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";
import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useMemo, useRef, useState } from "react";

import { Shell } from "../../components/Shell";
import {
  api,
  isAdmin,
  type IDSConfig,
  type IDSRule,
  type IDSRuleSource,
} from "../../lib/api";
import {
  ConfirmDialog,
  useConfirm,
} from "../../components/ConfirmDialog";
import { RulesTable } from "./ids-rules-table";
import {
  EditRuleModal,
  ExportPanel,
  GroupsPanel,
  ImportPanel,
  SourcesCatalog,
  type IDSPanelFields,
} from "./ids-panels";
import { isRuleEnabled } from "./ids-shared";

/* ── Page ── */

export default function IDSPage() {
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const draft = useConfigEditor<IDSConfig>({ enabled: false, rules: [] }, false);
  const { conflictProps, editor, cfg: ids, setCfg: setIds, readConfig: adoptConfig, write, writeRefresh, text, setText, clearText } = draft;
  const panelForm = useConfigForm<IDSPanelFields>({ name: "", filter: "", format: "", sigmaText: "" });
  const { readConfig: refreshForm } = panelForm;
  const refreshId = useRef(0);
  const [importPending, setImportPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [editing, setEditing] = useState<IDSRule | null>(null);
  const [sources, setSources] = useState<IDSRuleSource[]>([]);
  const [activeTab, setActiveTab] = useState<"rules" | "import" | "export" | "sources" | "groups">("rules");
  const confirm = useConfirm();

  const { refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const id = ++refreshId.current;
    const [cfgSnapshot, src] = await Promise.all([api.getIDS(), api.getIDSSources()]);
    const cfg = cfgSnapshot?.data;
    // A read started before an import cannot acknowledge or undo that import.
    if (id !== refreshId.current) return;
    if (!checkLoaded(cfg)) {
      setError("Failed to load IDS rules.");
      return;
    }
    setError(null);
    adoptConfig({ data: cfg, revision: cfgSnapshot?.revision ?? "" }, keepEdits);
    refreshForm({ data: cfg, revision: cfgSnapshot?.revision ?? "" }, keepEdits);
    setImportPending(false);
    setSources(src ?? []);
    if (!keepEdits) setEditing(null);
  }, [checkLoaded, adoptConfig, refreshForm]));

  useConfigRefresh(refresh);

  async function onSave() {
    if (!canEdit || !canSave || importPending || draft.stale) return;
    setError(null);
    // The modal is not submitted by the page Save button.
    const saved = await write((base, submitted) => api.setIDS(base, submitted), { replace: data => data, raw: {} });
    if (!saved.ok) { setError(revisionError(saved)); return; }
    flashSuccess("IDS rules staged — commit to apply.");
  }

  async function onImport(file: File, format: string) {
    if (importPending) return false;
    setImportPending(true);
    setError(null);
    const result = await writeRefresh(base => api.importIDSRules(base, file, format || undefined), api.getIDS,
      (view, before, next) => {
        const known = new Set((before.rules ?? []).map(rule => rule.id));
        const added = (next.rules ?? []).filter(rule => !known.has(rule.id));
        return { ...view, rules: added.reduce((rows, rule) => upsertRow(rows, rule, row => row.id), view.rules ?? []) };
      });
    if (!result.ok) {
      setImportPending(false);
      setError(revisionError(result));
      return false;
    }
    // The import response contains counts, not rules. Keep Save blocked until
    // a successful read has acknowledged the additions, even if that read fails.
    await refresh();
    const { imported, skipped, format: detected, total } = result.data;
    flashSuccess(`IDS rules staged — commit to apply. Imported ${imported} rule${imported !== 1 ? "s" : ""} (${skipped} skipped). Format: ${detected}. Total: ${total}.`);
    setActiveTab("rules");
    return true;
  }

  function onDelete(id: string) {
    if (!canEdit) return;
    confirm.open({
      title: "Remove IDS Rule",
      message: `Remove rule "${id}"? Unsaved until you click Save.`,
      confirmLabel: "Remove",
      variant: "danger",
      onConfirm: () => {
        setIds((prev) => ({ ...prev, rules: (prev.rules ?? []).filter((r) => r.id !== id) }));
      },
    });
  }

  function onBulkDelete(ruleIds: string[]) {
    if (!canEdit) return;
    confirm.open({
      title: "Remove selected rules",
      message: `Remove ${ruleIds.length} selected rule${ruleIds.length !== 1 ? "s" : ""}? Unsaved until you click Save.`,
      confirmLabel: "Remove",
      variant: "danger",
      onConfirm: () => {
        const set = new Set(ruleIds);
        setIds((prev) => ({ ...prev, rules: (prev.rules ?? []).filter((r) => !set.has(r.id)) }));
      },
    });
  }

  function onBulkToggle(ruleIds: string[], enabled: boolean) {
    if (!canEdit) return;
    const set = new Set(ruleIds);
    setIds((prev) => ({
      ...prev,
      rules: (prev.rules ?? []).map((r) => set.has(r.id) ? { ...r, enabled } : r),
    }));
  }

  function onToggleRule(id: string) {
    if (!canEdit) return;
    setIds((prev) => ({
      ...prev,
      rules: (prev.rules ?? []).map((r) => r.id === id ? { ...r, enabled: !isRuleEnabled(r) } : r),
    }));
  }

  function canCombinePanel(sourceRevision = panelForm.editor.baseRevision): boolean {
    const destinationRevision = draft.editor.baseRevision;
    if (sourceRevision === destinationRevision) return true;
    panelForm.requireReview(destinationRevision ?? "");
    return false;
  }

  function flashSuccess(msg: string) {
    setSuccess(msg);
    setTimeout(() => setSuccess(null), 4000);
  }

  const rules = useMemo(() => ids.rules ?? [], [ids.rules]);
  const groups = useMemo(() => ids.ruleGroups ?? [], [ids.ruleGroups]);
  const enabledCount = useMemo(() => rules.filter(isRuleEnabled).length, [rules]);

  const tabs = [
    { key: "rules" as const, label: "Rules", count: rules.length },
    { key: "groups" as const, label: "Groups", count: groups.length },
    { key: "import" as const, label: "Import" },
    { key: "export" as const, label: "Export" },
    { key: "sources" as const, label: "Sources", count: sources.length },
  ];

  return (
    <Shell
      title="IDS Rules"
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => refresh({ keepEdits: false })} className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui">
            Refresh
          </button>
          {canEdit && (
            <button onClick={onSave} disabled={!canSave || importPending || draft.stale} className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50">
              Save
            </button>
          )}
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice {...panelForm.conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={false} />
      <ConfigEditNotice {...conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={editor.superseded} />
      <fieldset disabled={!canSave} className="min-w-0">
      {error && <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">{error}</div>}
      {success && <div className="mb-4 rounded-xs border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">{success}</div>}

      <div className="mb-6 flex items-center gap-4">
        <label className="flex items-center gap-2 text-sm text-(--text)">
          <input type="checkbox" checked={!!ids.enabled} disabled={!canEdit}
            onChange={(e) => setIds({ ...ids, enabled: e.target.checked })}
            className="h-4 w-4 rounded-sm border-white/20 bg-(--surface)" />
          Enable IDS engine
        </label>
        <span className="ml-auto text-xs text-(--text-muted) tabular-nums">
          {enabledCount.toLocaleString()} / {rules.length.toLocaleString()} rules enabled
        </span>
      </div>

      {/* Tab bar */}
      <div className="mb-4 flex gap-1 border-b overflow-x-auto">
        {tabs.map((t) => (
          <button key={t.key} onClick={() => setActiveTab(t.key)}
            className={`shrink-0 px-4 py-2 text-sm transition-ui border-b-2 -mb-px ${
              activeTab === t.key ? "" : "border-transparent text-(--text-muted) hover:text-(--text)"
            }`}>
            {t.label}
            {t.count !== undefined && (
              <span className="ml-1.5 rounded-xs bg-white/6 px-1.5 py-0.5 text-xs tabular-nums">{t.count.toLocaleString()}</span>
            )}
          </button>
        ))}
      </div>

      {activeTab === "rules" && (
        <RulesTable rules={rules} canEdit={canEdit} onEdit={setEditing} onDelete={onDelete}
          onBulkDelete={onBulkDelete} onBulkToggle={onBulkToggle} onToggleRule={onToggleRule} />
      )}
      {activeTab === "groups" && (
        <GroupsPanel form={panelForm} groups={groups} rules={rules} canEdit={canEdit}
          onUpdate={(g) => {
            if (!canCombinePanel()) return false;
            setIds((prev) => ({ ...prev, ruleGroups: g }));
            return true;
          }} />
      )}
      {activeTab === "import" && canEdit && (
        <ImportPanel form={panelForm} onImport={onImport} onConverted={(rule, revision) => {
          if (!canCombinePanel(revision)) return false;
          // Conversion returns a rule but does not stage it on the server.
          setIds((current) => ({ ...current, rules: upsertRow(current.rules ?? [], rule, (r) => r.id) }));
          flashSuccess(`Converted Sigma rule: ${rule.id}. Click Save to persist.`);
          setActiveTab("rules");
          return true;
        }} onError={setError} />
      )}
      {activeTab === "import" && !canEdit && (
        <div className="py-8 text-center text-sm text-(--text-muted)">Import is disabled in view-only mode.</div>
      )}
      {activeTab === "export" && <ExportPanel ruleCount={rules.length} />}
      {activeTab === "sources" && <SourcesCatalog sources={sources} />}

      {editing && canEdit && (
        <EditRuleModal rule={editing}
          text={text(`rule.${editing.id}`, JSON.stringify(editing, null, 2))}
          setText={(value) => setText(`rule.${editing.id}`, value)}
          onClose={() => { clearText(`rule.${editing.id}`); setEditing(null); }} onSave={(newRule) => {
          setIds((prev) => ({ ...prev, rules: (prev.rules ?? []).map((r) => r.id === editing.id ? newRule : r) }));
          clearText(`rule.${editing.id}`);
          setEditing(null);
        }} />
      )}
      </fieldset>
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
