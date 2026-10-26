"use client";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";

import { api, isAdmin, type ConfigBackup, type ConfigBundle } from "../../lib/api";
import type { ConfigDiff } from "../../lib/api-config";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import {
  BlockKey,
  ConfigBlockExplorer,
  ViewerSource,
} from "./config-block-explorer";
import {
  ConfigActionBar,
  ConfigBackupRecoveryCard,
  ConfigSummaryCard,
  IDSRulesCard,
} from "./config-overview-panels";
import {
  buildBlockItems,
  buildDiffBlocks,
  findSelectedItem,
  getBlockValue,
  parseTab,
  TAB_META,
  type Tab,
} from "./config-utils";

export default function ConfigPageWrapper() {
  return (
    <Suspense>
      <ConfigPage />
    </Suspense>
  );
}

function ConfigPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const searchParams = useSearchParams();
  const initialTab = parseTab(searchParams.get("tab"));
  const [tab, setTab] = useState<Tab>(initialTab);
  const [configDiff, setConfigDiff] = useState<ConfigDiff | null>();
  const running = configDiff?.running ?? null;
  const candidate = configDiff?.candidate ?? null;
  const [candidateText, setCandidateText] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [ttlSeconds, setTtlSeconds] = useState("60");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [backupName, setBackupName] = useState("");
  const [backups, setBackups] = useState<ConfigBackup[]>([]);
  const [runningLoadedAt, setRunningLoadedAt] = useState<Date | null>(null);
  const [candidateLoadedAt, setCandidateLoadedAt] = useState<Date | null>(null);
  const [viewerSource, setViewerSource] = useState<ViewerSource>("running");
  const [selectedBlock, setSelectedBlock] = useState<BlockKey>("system");
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const selectedRef = useRef<HTMLDivElement | null>(null);

  async function refresh() {
    const d = await api.diffConfig();
    setConfigDiff(d);
    setCandidateText(
      JSON.stringify(d?.candidate ?? d?.running ?? {}, null, 2),
    );
    if (d?.running) setRunningLoadedAt(new Date());
    if (d?.candidate) setCandidateLoadedAt(new Date());
  }

  useConfigRefresh(refresh);

  useEffect(() => {
    refresh();
    refreshBackups();
  }, []);

  function statusWithWarning(base: string, warning?: string) {
    return warning ? `${base} Warning: ${warning}` : base;
  }

  async function saveCandidate() {
    if (!canEdit) return;
    setStatus(null);
    try {
      const parsed = JSON.parse(candidateText) as ConfigBundle;
      const res = await api.setCandidateConfig(parsed);
      if (!res.ok) {
        setStatus(`Failed to save candidate: ${res.error}`);
        return;
      }
      setCandidateLoadedAt(new Date());
      setStatus(statusWithWarning("Candidate staged — commit to apply.", res.warning));
      refresh();
    } catch (e) {
      setStatus("Invalid JSON.");
    }
  }

  async function copyRunningToCandidate() {
    if (!canEdit || !running) return;
    setStatus(null);
    const res = await api.setCandidateConfig(running);
    if (!res.ok) {
      setStatus(`Failed to copy running to candidate: ${res.error}`);
      return;
    }
    setCandidateText(JSON.stringify(running, null, 2));
    setCandidateLoadedAt(new Date());
    setStatus(statusWithWarning("Candidate replaced with running and staged — commit to apply.", res.warning));
    refresh();
  }

  function doCommit() {
    if (!canEdit) return;
    const changedCount = diffBlocks.length;
    confirm.open({
      title: "Commit configuration",
      message: changedCount > 0
        ? `This will apply ${changedCount} changed block${changedCount === 1 ? "" : "s"} from the candidate to the running config. This takes effect immediately.`
        : "This will promote the candidate config to running. No differences were detected — the configs may already be in sync.",
      confirmLabel: "Commit",
      variant: "default",
      onConfirm: async () => {
        setStatus(null);
        const result = await api.commit();
        if (result.ok) {
          setStatus(statusWithWarning("Committed.", result.warning));
        } else {
          setStatus(`Commit failed: ${result.error}`);
        }
        refresh();
      },
    });
  }

  function doCommitConfirmed() {
    if (!canEdit) return;
    const ttl = Number(ttlSeconds);
    const secs = Number.isFinite(ttl) && ttl > 0 ? ttl : 60;
    confirm.open({
      title: "Commit with auto-rollback",
      message: `This will apply the candidate config for ${secs} seconds. If you do not click "Confirm" before the timer expires, the config will automatically roll back to the previous running state. Use this for risky changes.`,
      confirmLabel: "Start timer",
      variant: "default",
      onConfirm: async () => {
        setStatus(null);
        const result = await api.commitConfirmed(secs);
        setStatus(result.ok ? statusWithWarning(`Commit-confirmed started (${secs}s).`, result.warning) : `Commit-confirmed failed: ${result.error}`);
        refresh();
      },
    });
  }

  async function doConfirm() {
    if (!canEdit) return;
    setStatus(null);
    const result = await api.confirmCommit();
    setStatus(result.ok ? statusWithWarning("Commit confirmed.", result.warning) : `Confirm failed: ${result.error}`);
    refresh();
  }

  function doRollback() {
    if (!canEdit) return;
    confirm.open({
      title: "Rollback configuration",
      message:
        "This will restore the previous running config (from before the last commit). Any changes made since the last commit — including new zones, rules, or interfaces — will be lost. This cannot be undone.",
      confirmLabel: "Rollback",
      variant: "danger",
      onConfirm: async () => {
        setStatus(null);
        const result = await api.rollback();
        if (result.ok) {
          setStatus(statusWithWarning("Rolled back.", result.warning));
        } else {
          setStatus(`Rollback failed: ${result.error}`);
        }
        refresh();
      },
    });
  }

  async function downloadConfig(redacted: boolean) {
    setStatus(null);
    const cfg = await api.exportConfig(redacted);
    if (!cfg) {
      setStatus("Failed to export config.");
      return;
    }
    const blob = new Blob([JSON.stringify(cfg, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const suffix = redacted ? "redacted" : "full";
    a.href = url;
    a.download = `containd-config-${suffix}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setStatus("Config downloaded.");
  }

  async function restoreConfig() {
    if (!canEdit) return;
    setStatus(null);
    if (!uploadFile) {
      setStatus("Select a config JSON file first.");
      return;
    }
    try {
      const text = await uploadFile.text();
      const parsed = JSON.parse(text) as ConfigBundle;
      const res = await api.importConfig(parsed);
      setStatus(res.ok ? statusWithWarning("Config import staged — commit to apply.", res.warning) : `Restore failed: ${res.error}`);
      refresh();
    } catch {
      setStatus("Invalid JSON file.");
    }
  }

  async function refreshBackups() {
    const list = await api.listConfigBackups();
    setBackups(list ?? []);
  }

  async function createBackup(redacted: boolean) {
    if (!canEdit) return;
    setStatus(null);
    const res = await api.createConfigBackup({
      name: backupName.trim() ? backupName.trim() : undefined,
      redacted,
    });
    if (!res.ok) {
      setStatus(`Failed to create backup: ${res.error}`);
      return;
    }
    setBackupName("");
    setStatus(statusWithWarning("Backup saved on appliance.", res.warning));
    refreshBackups();
  }

  async function downloadBackup(backup: ConfigBackup) {
    setStatus(null);
    const blob = await api.downloadConfigBackup(backup.id);
    if (!blob) {
      setStatus("Failed to download backup.");
      return;
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${backup.name || "containd-config-backup"}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setStatus("Backup downloaded.");
  }

  async function deleteBackup(backup: ConfigBackup) {
    if (!canEdit) return;
    confirm.open({
      title: "Delete backup",
      message: `Delete backup "${backup.name}"? This cannot be undone.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: async () => {
        setStatus(null);
        const res = await api.deleteConfigBackup(backup.id);
        if (!res.ok) {
          setStatus(`Failed to delete backup: ${res.error}`);
          return;
        }
        setStatus(statusWithWarning("Backup deleted.", res.warning));
        refreshBackups();
      },
    });
  }

  const runningText = useMemo(
    () => JSON.stringify(running ?? {}, null, 2),
    [running],
  );
  const diffBlocks = useMemo(
    () => buildDiffBlocks(configDiff),
    [configDiff],
  );

  const viewerConfig = viewerSource === "running" ? running : candidate;
  const blockItems = useMemo(
    () => buildBlockItems(selectedBlock, viewerConfig),
    [selectedBlock, viewerConfig],
  );

  const selectedItem = useMemo(
    () => findSelectedItem(selectedBlock, selectedItemId, viewerConfig),
    [selectedBlock, selectedItemId, viewerConfig],
  );

  useEffect(() => {
    if (selectedRef.current) {
      selectedRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [selectedItemId]);
  const blockValue = useMemo(
    () => getBlockValue(selectedBlock, viewerConfig),
    [viewerConfig, selectedBlock],
  );

  const zoneCount = running?.zones?.length ?? 0;
  const ifaceCount = running?.interfaces?.length ?? 0;
  const ruleCount = running?.firewall?.rules?.length ?? 0;
  const assetCount = running?.assets?.length ?? 0;
  const idsRuleCount = configDiff?.idsBank?.running.count ?? 0;
  const objectCount = running?.objects?.length ?? 0;
  const dpiMode = (running as any)?.dataplane?.dpiMode ?? "off";
  const tips: Tip[] = [
    {
      id: "config:backup",
      title: "Backup your config",
      body: "Download a redacted backup for sharing, full backup for recovery.",
      when: () => true,
    },
    {
      id: "config:restore",
      title: "Restore carefully",
      body: "Restore replaces the candidate config; use commit-confirmed if you need a safe rollback window.",
      when: () => canEdit,
    },
    {
      id: "config:viewer",
      title: "Explore by block",
      body: "Use the left list to jump between zones, interfaces, services, and policy blocks.",
      when: () => true,
    },
    {
      id: "config:apply",
      title: "Staged changes do not apply automatically",
      body: "Edit the staged config, review the diff, then commit or commit-confirmed to update runtime behavior.",
      when: () => true,
    },
  ];

  return (
    <Shell
      title="Config"
      actions={
        <button
          onClick={refresh}
          className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
        >
          Refresh
        </button>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <div className="mb-4 flex flex-wrap gap-2">
        {(["overview", "running", "candidate", "diff"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            title={TAB_META[t].description}
            className={
              tab === t
                ? "rounded-xs px-3 py-1.5 text-sm text-(--text) transition-ui"
                : "rounded-xs px-3 py-1.5 text-sm text-(--text-muted) hover:text-(--text) transition-ui"
            }
          >
            {TAB_META[t].label}
          </button>
        ))}
      </div>
      <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-xs text-(--text)">
        Workflow: edit the staged config, review the change summary, then commit or commit-confirmed to update the live appliance safely.
      </div>

      {status && (
        <div
          className={`mb-4 rounded-xs px-4 py-3 text-sm ${
            status.includes("failed") || status.includes("Failed") || status === "Invalid JSON." || status === "Invalid JSON file."
              ? "border border-red-500/30 bg-red-500/10 text-red-400"
              : status.includes("staged") || status.includes("saved") || status.includes("Committed") || status.includes("confirmed") || status.includes("restored") || status.includes("downloaded") || status.includes("deleted") || status.includes("Rolled back") || status.includes("replaced")
                ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border bg-(--surface) text-(--text)"
          }`}
        >
          {status}
        </div>
      )}

      {tab === "overview" && (
        <div className="grid gap-4">
          <TipsBanner tips={tips} />
          <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
            <ConfigBackupRecoveryCard
              backupName={backupName}
              backups={backups}
              canEdit={canEdit}
              onBackupNameChange={setBackupName}
              onCreateBackup={createBackup}
              onDeleteBackup={deleteBackup}
              onDownloadBackup={downloadBackup}
              onDownloadConfig={downloadConfig}
              onRestoreConfig={restoreConfig}
              onUploadFileChange={setUploadFile}
            />
            <ConfigSummaryCard
              zoneCount={zoneCount}
              ifaceCount={ifaceCount}
              ruleCount={ruleCount}
              assetCount={assetCount}
              objectCount={objectCount}
              idsRuleCount={idsRuleCount}
              dpiMode={dpiMode}
            />
          </div>

          <IDSRulesCard
            canEdit={canEdit}
            idsRuleCount={idsRuleCount}
            onDownloadRules={async () => {
              setStatus(null);
              const blob = await api.backupIDSRules();
              if (!blob) {
                setStatus("Failed to export IDS rules.");
                return;
              }
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "containd-ids-rules.json";
              a.click();
              URL.revokeObjectURL(url);
              setStatus("IDS rules downloaded.");
            }}
            onRestoreRules={async (file) => {
              if (!file) return;
              setStatus(null);
              try {
                const text = await file.text();
                const rules = JSON.parse(text);
                if (!Array.isArray(rules)) {
                  setStatus("Invalid IDS rules file (expected JSON array).");
                  return;
                }
                const res = await api.restoreIDSRules(rules);
                setStatus(res.ok ? `IDS restore staged (${res.data.count} rules) — commit to apply.` : `Restore failed: ${res.error}`);
                refresh();
              } catch {
                setStatus("Invalid JSON file.");
              }
            }}
          />

          <ConfigBlockExplorer
            viewerSource={viewerSource}
            setViewerSource={setViewerSource}
            selectedBlock={selectedBlock}
            setSelectedBlock={setSelectedBlock}
            selectedItemId={selectedItemId}
            setSelectedItemId={setSelectedItemId}
            blockItems={blockItems}
            selectedItem={selectedItem}
            blockValue={blockValue}
            viewerConfig={viewerConfig}
            idsBankCount={configDiff?.idsBank?.[viewerSource].count ?? null}
            setSelectedRef={(node) => {
              selectedRef.current = node;
            }}
          />

          <ConfigActionBar
            canEdit={canEdit}
            ttlSeconds={ttlSeconds}
            onTtlChange={setTtlSeconds}
            onCommit={doCommit}
            onCommitConfirmed={doCommitConfirmed}
            onConfirmCommit={doConfirm}
            onRollback={doRollback}
          />
        </div>
      )}

      {tab === "candidate" && (
        <Card padding="md">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-(--text)">Staged config JSON</h2>
              <div className="text-xs text-(--text-muted)">
                {candidateLoadedAt
                  ? `Last saved ${candidateLoadedAt.toLocaleString()}`
                  : "Not saved yet"}
              </div>
            </div>
            {canEdit && (
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={copyRunningToCandidate}
                  className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
                >
                  Copy running → staged
                </button>
                <button
                  onClick={saveCandidate}
                  className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
                >
                  Save staged config
                </button>
              </div>
            )}
          </div>
          <div className="mb-3 text-xs text-(--text-muted)">
            Changes here are saved but not active until you review and commit them.
          </div>
          <textarea
            aria-label="Staged config JSON"
            value={candidateText}
            onChange={(e) => setCandidateText(e.target.value)}
            readOnly={!canEdit}
            rows={22}
            className="w-full rounded-xs border bg-(--surface) p-3 font-mono text-xs text-(--text) transition-ui outline-hidden"
          />
        </Card>
      )}

      {tab === "running" && (
        <div className="rounded-xs border bg-(--surface) p-4 text-xs text-(--text) shadow-card">
          <div className="mb-3 flex items-center justify-between text-xs text-(--text-muted)">
            <div>Running config</div>
            <div>{runningLoadedAt ? `Loaded ${runningLoadedAt.toLocaleString()}` : "Not loaded yet"}</div>
          </div>
          <div className="mb-3 text-xs text-(--text-muted)">
            This is the last committed config, not proof of live enforcement.
          </div>
          <pre>{runningText}</pre>
        </div>
      )}

      {tab === "diff" && (
        <div className="grid gap-4">
          {candidateLoadedAt && runningLoadedAt && candidateLoadedAt < runningLoadedAt && (
            <div className="rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 shadow-card">
              Staged config looks older than running config. Copy running → staged first if you want to review your latest committed state.
            </div>
          )}
          {configDiff === undefined ? (
            <div className="rounded-xs border bg-(--surface) p-4 text-sm text-(--text) shadow-card">
              Loading configuration changes…
            </div>
          ) : configDiff === null ? (
            <div role="alert" className="rounded-xs border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400 shadow-card">
              Unable to load configuration changes. Use Refresh to try again.
            </div>
          ) : !candidate ? (
            <div className="rounded-xs border bg-(--surface) p-4 text-sm text-(--text) shadow-card">
              No staged config to compare. Save staged changes to review them here.
            </div>
          ) : !configDiff.changed ? (
            <div className="rounded-xs border bg-(--surface) p-4 text-sm text-(--text) shadow-card">
              No differences between running and staged config.
            </div>
          ) : (
            diffBlocks.map((block) => (
              <div
                key={block.key}
                role="region"
                aria-label={`${block.label} changes`}
                className="rounded-xs border bg-(--surface) p-4 shadow-card"
              >
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] text-(--text-dim)">Changed block</div>
                    <div className="text-sm font-semibold text-(--text)">{block.label}</div>
                  </div>
                  {block.diff.length > 0 && (
                    <div className="text-xs text-(--text-muted)">
                      {block.diff.filter((l) => l.type === "add").length} added ·{" "}
                      {block.diff.filter((l) => l.type === "del").length} removed
                    </div>
                  )}
                </div>
                {block.hiddenChanges && (
                  <p className="text-sm text-(--text)">Secret values changed (hidden).</p>
                )}
                {block.idsBank && (
                  <div className="mb-3 grid gap-1 text-xs text-(--text)">
                    <div className="font-semibold">IDS rule bank</div>
                    <div>
                      Running: {block.idsBank.running.count.toLocaleString()} rules · SHA-256{" "}
                      <span className="font-mono">{block.idsBank.running.sha256.slice(0, 12)}</span>
                    </div>
                    <div>
                      Staged: {block.idsBank.candidate.count.toLocaleString()} rules · SHA-256{" "}
                      <span className="font-mono">{block.idsBank.candidate.sha256.slice(0, 12)}</span>
                    </div>
                  </div>
                )}
                {block.diff.length > 0 && (
                  <div className="grid gap-1 rounded-xs border bg-black/60 p-3 text-xs text-(--text)">
                    {block.diff.map((line, idx) => (
                      <div
                        key={`${block.key}-${idx}`}
                        className={
                          line.type === "add"
                            ? "rounded-sm bg-mint/20 px-2 py-0.5 text-mint"
                            : "rounded-sm bg-rose-500/20 px-2 py-0.5 text-rose-200"
                        }
                      >
                        <span className="mr-2 inline-block w-3 text-center">
                          {line.type === "add" ? "+" : "-"}
                        </span>
                        <span className="break-all font-mono whitespace-pre-wrap">{line.line}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {tab !== "overview" && (
        <ConfigActionBar
          canEdit={canEdit}
          ttlSeconds={ttlSeconds}
          onTtlChange={setTtlSeconds}
          onCommit={doCommit}
          onCommitConfirmed={doCommitConfirmed}
          onConfirmCommit={doConfirm}
          onRollback={doRollback}
        />
      )}
    </Shell>
  );
}
