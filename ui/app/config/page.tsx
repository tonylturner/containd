"use client";

import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";

import { api, isAdmin, type ConfigBackup, type ConfigBundle } from "../../lib/api";
import { Shell } from "../../components/Shell";
import { TipsBanner, type Tip } from "../../components/TipsBanner";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

type Tab = "overview" | "running" | "candidate" | "diff";
type ViewerSource = "running" | "candidate";
type BlockKey =
  | "system"
  | "zones"
  | "interfaces"
  | "routing"
  | "firewall"
  | "nat"
  | "portForwards"
  | "assets"
  | "ids"
  | "services"
  | "dataPlane"
  | "pcap";

type DiffLine = { type: "add" | "del" | "same"; line: string };

function diffLines(aLines: string[], bLines: string[]): DiffLine[] {
  const n = aLines.length;
  const m = bLines.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => Array(m + 1).fill(0));
  for (let i = 1; i <= n; i += 1) {
    for (let j = 1; j <= m; j += 1) {
      if (aLines[i - 1] === bLines[j - 1]) dp[i][j] = dp[i - 1][j - 1] + 1;
      else dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = n;
  let j = m;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && aLines[i - 1] === bLines[j - 1]) {
      out.push({ type: "same", line: aLines[i - 1] });
      i -= 1;
      j -= 1;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      out.push({ type: "add", line: bLines[j - 1] });
      j -= 1;
    } else if (i > 0) {
      out.push({ type: "del", line: aLines[i - 1] });
      i -= 1;
    }
  }
  return out.reverse();
}

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
  const initialTab = (searchParams.get("tab") as Tab) || "overview";
  const [tab, setTab] = useState<Tab>(initialTab);
  const [running, setRunning] = useState<ConfigBundle | null>(null);
  const [candidate, setCandidate] = useState<ConfigBundle | null>(null);
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
    setRunning(d?.running ?? null);
    setCandidate(d?.candidate ?? null);
    setCandidateText(
      JSON.stringify(d?.candidate ?? d?.running ?? {}, null, 2),
    );
    if (d?.running) setRunningLoadedAt(new Date());
    if (d?.candidate) setCandidateLoadedAt(new Date());
  }

  useEffect(() => {
    refresh();
    refreshBackups();
  }, []);

  async function saveCandidate() {
    if (!canEdit) return;
    setStatus(null);
    try {
      const parsed = JSON.parse(candidateText) as ConfigBundle;
      const res = await api.setCandidateConfig(parsed);
      if (!res) {
        setStatus("Failed to save candidate.");
        return;
      }
      setCandidateLoadedAt(new Date());
      setStatus("Candidate saved.");
      refresh();
    } catch (e) {
      setStatus("Invalid JSON.");
    }
  }

  async function copyRunningToCandidate() {
    if (!canEdit || !running) return;
    setStatus(null);
    const res = await api.setCandidateConfig(running);
    if (!res) {
      setStatus("Failed to copy running to candidate.");
      return;
    }
    setCandidateText(JSON.stringify(running, null, 2));
    setCandidateLoadedAt(new Date());
    setStatus("Candidate replaced with running.");
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
        const res = await api.commit();
        setStatus(res ? "Committed." : "Commit failed.");
        if (res) window.dispatchEvent(new CustomEvent("containd:config:committed"));
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
        const res = await api.commitConfirmed(secs);
        setStatus(res ? `Commit-confirmed started (${secs}s).` : "Commit-confirmed failed.");
        refresh();
      },
    });
  }

  async function doConfirm() {
    if (!canEdit) return;
    setStatus(null);
    const result = await api.confirmCommit();
    setStatus(result.ok ? "Commit confirmed." : `Confirm failed: ${result.error}`);
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
        const res = await api.rollback();
        setStatus(res ? "Rolled back." : "Rollback failed.");
        if (res) window.dispatchEvent(new CustomEvent("containd:config:committed"));
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
      setStatus(res ? "Config restored." : "Restore failed.");
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
    if (!res) {
      setStatus("Failed to create backup.");
      return;
    }
    setBackupName("");
    setStatus("Backup saved on appliance.");
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
        if (!res) {
          setStatus("Failed to delete backup.");
          return;
        }
        setStatus("Backup deleted.");
        refreshBackups();
      },
    });
  }

  function formatBytes(size: number) {
    if (!Number.isFinite(size)) return "-";
    if (size < 1024) return `${size} B`;
    const kb = size / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    const mb = kb / 1024;
    if (mb < 1024) return `${mb.toFixed(1)} MB`;
    const gb = mb / 1024;
    return `${gb.toFixed(1)} GB`;
  }

  const runningText = useMemo(
    () => JSON.stringify(running ?? {}, null, 2),
    [running],
  );
  const diffBlocks = useMemo(() => {
    if (!candidate) return [];
    const r = running ?? {};
    const c = candidate;
    const blocks: { key: BlockKey; label: string; running: unknown; candidate: unknown }[] = [
      { key: "system", label: "System", running: (r as any).system, candidate: (c as any).system },
      { key: "zones", label: "Zones", running: (r as any).zones, candidate: (c as any).zones },
      { key: "interfaces", label: "Interfaces", running: (r as any).interfaces, candidate: (c as any).interfaces },
      { key: "routing", label: "Routing", running: (r as any).routing, candidate: (c as any).routing },
      { key: "firewall", label: "Firewall rules", running: (r as any).firewall?.rules, candidate: (c as any).firewall?.rules },
      { key: "nat", label: "NAT", running: (r as any).firewall?.nat, candidate: (c as any).firewall?.nat },
      { key: "portForwards", label: "Port forwards", running: (r as any).firewall?.portForwards, candidate: (c as any).firewall?.portForwards },
      { key: "assets", label: "Assets", running: (r as any).assets, candidate: (c as any).assets },
      { key: "ids", label: "IDS", running: (r as any).ids, candidate: (c as any).ids },
      { key: "services", label: "Services", running: (r as any).services, candidate: (c as any).services },
      { key: "dataPlane", label: "Data plane", running: (r as any).dataplane, candidate: (c as any).dataplane },
      { key: "pcap", label: "PCAP", running: (r as any).pcap, candidate: (c as any).pcap },
    ];
    return blocks
      .map((block) => {
        const same = JSON.stringify(block.running ?? null) === JSON.stringify(block.candidate ?? null);
        if (same) return null;
        const runningLines = JSON.stringify(block.running ?? null, null, 2).split("\n");
        const candidateLines = JSON.stringify(block.candidate ?? null, null, 2).split("\n");
        const diff = diffLines(runningLines, candidateLines).filter((line) => line.type !== "same");
        return diff.length === 0 ? null : { ...block, diff };
      })
      .filter(Boolean) as Array<{
        key: BlockKey;
        label: string;
        running: unknown;
        candidate: unknown;
        diff: DiffLine[];
      }>;
  }, [running, candidate]);

  const viewerConfig = viewerSource === "running" ? running : candidate;
  type BlockItem = {
    id: string;
    label: string;
    meta: string;
  };

  const blockItems = useMemo<BlockItem[]>(() => {
    if (!viewerConfig) return [];
    const cfg = viewerConfig as any;
    switch (selectedBlock) {
      case "zones":
        return (cfg.zones ?? []).map((z: any): BlockItem => ({
          id: String(z.name),
          label: z.alias ? `${z.alias} (${z.name})` : String(z.name),
          meta: z.description || "Zone",
        }));
      case "interfaces":
        return (cfg.interfaces ?? []).map((i: any): BlockItem => ({
          id: String(i.name),
          label: i.alias ? `${i.alias} (${i.name})` : String(i.name),
          meta: [i.zone || "no zone", i.device || "no device"].join(" · "),
        }));
      case "firewall":
        return (cfg.firewall?.rules ?? []).map((r: any): BlockItem => ({
          id: String(r.id),
          label: String(r.id),
          meta: r.action ? `Action ${r.action}` : "Rule",
        }));
      case "assets":
        return (cfg.assets ?? []).map((a: any): BlockItem => ({
          id: String(a.id || a.name),
          label: String(a.name || a.id),
          meta: a.zone || a.type || "Asset",
        }));
      default:
        return [];
    }
  }, [selectedBlock, viewerConfig]);

  const selectedItem = useMemo(() => {
    if (!viewerConfig || !selectedItemId) return null;
    const cfg = viewerConfig as any;
    switch (selectedBlock) {
      case "zones":
        return (cfg.zones ?? []).find((z: any) => z.name === selectedItemId) ?? null;
      case "interfaces":
        return (cfg.interfaces ?? []).find((i: any) => i.name === selectedItemId) ?? null;
      case "firewall":
        return (cfg.firewall?.rules ?? []).find((r: any) => r.id === selectedItemId) ?? null;
      case "assets":
        return (cfg.assets ?? []).find(
          (a: any) => (a.id || a.name) === selectedItemId,
        ) ?? null;
      default:
        return null;
    }
  }, [selectedBlock, selectedItemId, viewerConfig]);

  useEffect(() => {
    if (selectedRef.current) {
      selectedRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [selectedItemId]);
  const blockValue = useMemo(() => {
    if (!viewerConfig) return null;
    const cfg = viewerConfig as any;
    switch (selectedBlock) {
      case "system":
        return cfg.system;
      case "zones":
        return cfg.zones;
      case "interfaces":
        return cfg.interfaces;
      case "routing":
        return cfg.routing;
      case "firewall":
        return cfg.firewall?.rules;
      case "nat":
        return cfg.firewall?.nat;
      case "portForwards":
        return cfg.firewall?.nat?.portForwards;
      case "assets":
        return cfg.assets;
      case "ids":
        return cfg.ids;
      case "services":
        return cfg.services;
      case "dataPlane":
        return cfg.dataPlane;
      case "pcap":
        return cfg.pcap;
      default:
        return null;
    }
  }, [viewerConfig, selectedBlock]);

  const zoneCount = running?.zones?.length ?? 0;
  const ifaceCount = running?.interfaces?.length ?? 0;
  const ruleCount = running?.firewall?.rules?.length ?? 0;
  const assetCount = running?.assets?.length ?? 0;
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
      body: "Restore replaces the running config; use commit-confirmed to stay safe.",
      when: () => canEdit,
    },
    {
      id: "config:viewer",
      title: "Explore by block",
      body: "Use the left list to jump between zones, interfaces, and policies.",
      when: () => true,
    },
  ];

  return (
    <Shell
      title="Config"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
        >
          Refresh
        </button>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {!canEdit && (
        <div className="mb-4 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <div className="mb-4 flex flex-wrap gap-2">
        {(["overview", "running", "candidate", "diff"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={
              tab === t
                ? "rounded-lg bg-white/[0.08] px-3 py-1.5 text-sm text-white transition-ui"
                : "rounded-lg px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-ui"
            }
          >
            {t}
          </button>
        ))}
      </div>

      {status && (
        <div
          className={`mb-4 rounded-xl px-4 py-3 text-sm ${
            status.includes("failed") || status.includes("Failed") || status === "Invalid JSON." || status === "Invalid JSON file."
              ? "border border-red-500/30 bg-red-500/10 text-red-400"
              : status.includes("saved") || status.includes("Committed") || status.includes("confirmed") || status.includes("restored") || status.includes("downloaded") || status.includes("deleted") || status.includes("Rolled back") || status.includes("replaced")
                ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border border-white/[0.08] bg-white/[0.03] text-slate-200"
          }`}
        >
          {status}
        </div>
      )}

      {tab === "overview" && (
        <div className="grid gap-4">
          <TipsBanner tips={tips} />
          <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
            <Card padding="lg">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                    Backup &amp; Restore
                  </div>
                  <h2 className="text-lg font-semibold text-[var(--text)]">Config vault</h2>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => downloadConfig(true)}
                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
                  >
                    Download redacted
                  </button>
                  {canEdit && (
                    <button
                      onClick={() => downloadConfig(false)}
                      className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 transition-ui"
                    >
                      Download full
                    </button>
                  )}
                </div>
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-[1.2fr_1fr_auto]">
                <input
                  type="file"
                  accept=".json"
                  onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
                  disabled={!canEdit}
                  className="rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 text-sm text-slate-200 transition-ui focus:border-blue-500/40 outline-none"
                />
                <div className="text-xs text-[var(--text-muted)]">
                  Restore replaces running config. Use redacted backups for sharing.
                </div>
                {canEdit && (
                  <button
                    onClick={restoreConfig}
                    className="rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-ui"
                  >
                    Restore
                  </button>
                )}
              </div>
              <div className="mt-4 rounded-xl border border-white/[0.08] bg-white/[0.03] p-4 shadow-card">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-dim)]">
                      Appliance backups
                    </div>
                    <div className="text-sm text-[var(--text)]">Store backups on the firewall.</div>
                  </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => createBackup(true)}
                    disabled={!canEdit}
                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-xs text-slate-200 hover:bg-white/[0.06] transition-ui"
                  >
                    Save redacted
                  </button>
                  {canEdit && (
                      <button
                        onClick={() => createBackup(false)}
                        className="rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition-ui"
                      >
                        Save full
                      </button>
                    )}
                  </div>
                </div>
                <div className="mt-3 grid gap-2 md:grid-cols-[1fr_auto]">
                  <input
                    value={backupName}
                    onChange={(e) => setBackupName(e.target.value)}
                    placeholder="Name this backup (optional)"
                    disabled={!canEdit}
                    className="rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 text-sm text-slate-200 transition-ui focus:border-blue-500/40 outline-none"
                  />
                  <div className="text-xs text-[var(--text-muted)]">
                    Backups are stored under the appliance data volume.
                  </div>
                </div>
                <div className="mt-3 grid gap-2">
                  {backups.length === 0 ? (
                    <div className="rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 text-xs text-slate-400">
                      No backups saved yet.
                    </div>
                  ) : (
                    backups.map((backup) => (
                      <div
                        key={backup.id}
                        className="grid gap-2 rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 text-xs text-slate-300 md:grid-cols-[1fr_auto]"
                      >
                        <div>
                          <div className="font-semibold text-[var(--text)]">{backup.name}</div>
                          <div className="text-[11px] text-[var(--text-muted)]">
                            {new Date(backup.createdAt).toLocaleString()} · {formatBytes(backup.size)} ·{" "}
                            {backup.redacted ? "Redacted" : "Full"} · ID {backup.id.slice(0, 6)}
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center justify-end gap-2">
                          <button
                            onClick={() => downloadBackup(backup)}
                            className="rounded-md border border-white/[0.08] bg-white/[0.03] px-2 py-1 text-xs text-slate-200 hover:bg-white/[0.06] transition-ui"
                          >
                            Download
                          </button>
                          {canEdit && (
                            <button
                              onClick={() => deleteBackup(backup)}
                              className="rounded-md bg-red-600/20 px-2 py-1 text-xs text-red-400 hover:bg-red-600/30 transition-ui"
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </Card>
            <Card padding="lg">
              <div className="text-xs uppercase tracking-[0.2em] text-slate-400">
                Config health
              </div>
              <div className="mt-3 grid gap-3 text-sm">
                <Stat label="Zones" value={zoneCount} />
                <Stat label="Interfaces" value={ifaceCount} />
                <Stat label="Firewall rules" value={ruleCount} />
                <Stat label="Assets" value={assetCount} />
              </div>
              <div className="mt-4 text-xs text-[var(--text-muted)]">
                Build your config by defining zones, then binding interfaces, then adding policies.
              </div>
            </Card>
          </div>

          <Card padding="lg">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  Config viewer
                </div>
                <h2 className="text-lg font-semibold text-[var(--text)]">Explore blocks</h2>
              </div>
              <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
                <span>Source</span>
                <button
                  onClick={() => setViewerSource("running")}
                  className={
                    viewerSource === "running"
                      ? "rounded-md bg-white/[0.08] px-2 py-1 text-white transition-ui"
                      : "rounded-md px-2 py-1 text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-ui"
                  }
                >
                  running
                </button>
                <button
                  onClick={() => setViewerSource("candidate")}
                  className={
                    viewerSource === "candidate"
                      ? "rounded-md bg-white/[0.08] px-2 py-1 text-white transition-ui"
                      : "rounded-md px-2 py-1 text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-ui"
                  }
                >
                  candidate
                </button>
              </div>
            </div>
            <div className="mt-4 grid gap-4 lg:grid-cols-[240px_1fr]">
              <div className="grid gap-2">
                {(
                  [
                    { key: "system", label: "System", help: "Appliance identity, management listeners, SSH." },
                    { key: "zones", label: "Zones", help: "Security zones used by policies and interfaces." },
                    { key: "interfaces", label: "Interfaces", help: "Port bindings, IPs, and zone mapping." },
                    { key: "routing", label: "Routing", help: "Gateways, routes, and policy routing rules." },
                    { key: "firewall", label: "Firewall rules", help: "Allow/deny policies and zone matches." },
                    { key: "nat", label: "NAT", help: "SNAT/DNAT settings for egress and port forwards." },
                    { key: "portForwards", label: "Port forwards", help: "Inbound DNAT mappings." },
                    { key: "assets", label: "Assets", help: "OT/ICS asset inventory and tags." },
                    { key: "ids", label: "IDS", help: "Detection rules and settings." },
                    { key: "services", label: "Services", help: "DNS, proxy, VPN, and system services." },
                    { key: "dataPlane", label: "Data plane", help: "Enforcement toggles and capture." },
                    { key: "pcap", label: "PCAP", help: "Capture settings and forwarding." },
                  ] as { key: BlockKey; label: string; help: string }[]
                ).map((item) => (
                  <button
                    key={item.key}
                    onClick={() => {
                      setSelectedBlock(item.key);
                      setSelectedItemId(null);
                    }}
                    title={item.help}
                    className={
                      selectedBlock === item.key
                        ? "rounded-lg bg-white/[0.08] px-3 py-2 text-left text-sm text-white transition-ui"
                        : "rounded-lg px-3 py-2 text-left text-sm text-slate-400 hover:text-slate-200 hover:bg-white/[0.04] transition-ui"
                    }
                  >
                    {item.label}
                  </button>
                ))}
              </div>
              <div className="grid gap-3">
                {blockItems.length > 0 && (
                  <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] p-3 shadow-card">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                        {selectedBlock} entries
                      </div>
                      <span className="text-xs text-[var(--text-muted)]">{blockItems.length} items</span>
                    </div>
                    <div className="mt-2 grid gap-1 md:grid-cols-2">
                      {blockItems.map((item: BlockItem) => (
                        <button
                          key={item.id}
                          onClick={() => setSelectedItemId(item.id)}
                          className={
                            selectedItemId === item.id
                              ? "rounded-lg border border-white/[0.08] bg-white/[0.08] px-2 py-1 text-left text-xs text-white transition-ui"
                              : "rounded-lg border border-white/[0.08] bg-white/[0.03] px-2 py-1 text-left text-xs text-slate-200 hover:bg-white/[0.06] transition-ui"
                          }
                        >
                          <div className="font-semibold">{item.label}</div>
                          <div className="text-[11px] text-[var(--text-muted)]">{item.meta}</div>
                        </button>
                      ))}
                    </div>
                    {selectedItem && (
                      <div className="mt-3 rounded-lg border border-white/[0.08] bg-black/40 p-3 text-xs text-slate-100">
                        <div className="mb-2 flex items-center justify-between">
                          <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                            Selected
                          </div>
                          {selectedBlock === "zones" && (
                            <a href="/zones/" className="text-xs text-blue-400 hover:text-blue-300 transition-ui">
                              Open Zones
                            </a>
                          )}
                          {selectedBlock === "interfaces" && (
                            <a href="/interfaces/" className="text-xs text-blue-400 hover:text-blue-300 transition-ui">
                              Open Interfaces
                            </a>
                          )}
                          {selectedBlock === "firewall" && (
                            <a href="/firewall/" className="text-xs text-blue-400 hover:text-blue-300 transition-ui">
                              Open Firewall
                            </a>
                          )}
                          {selectedBlock === "assets" && (
                            <a href="/assets/" className="text-xs text-blue-400 hover:text-blue-300 transition-ui">
                              Open Assets
                            </a>
                          )}
                        </div>
                        <pre className="whitespace-pre-wrap">
{JSON.stringify(selectedItem, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
                <div className="rounded-xl border border-white/[0.08] bg-black/40 p-4 text-xs text-slate-100">
                  {viewerConfig ? (
                    Array.isArray(blockValue) ? (
                      blockValue.length === 0 ? (
                        <div className="text-[var(--text-muted)]">No entries in this block.</div>
                      ) : (
                        <div className="grid gap-2">
                          {blockValue.map((item: any) => {
                            const id = item?.id || item?.name;
                            const isSelected = selectedItemId && id === selectedItemId;
                            return (
                              <div
                                key={id ?? JSON.stringify(item)}
                                role="button"
                                tabIndex={0}
                                onClick={() => {
                                  if (id) setSelectedItemId(id);
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter" && id) setSelectedItemId(id);
                                }}
                                ref={isSelected ? selectedRef : undefined}
                                className={
                                  isSelected
                                    ? "rounded-lg border border-blue-500/40 bg-blue-500/10 p-3 transition-ui"
                                    : "rounded-lg border border-white/[0.08] bg-black/30 p-3 hover:border-white/[0.12] transition-ui"
                                }
                              >
                                <pre className="whitespace-pre-wrap">
{JSON.stringify(item, null, 2)}
                                </pre>
                              </div>
                            );
                          })}
                        </div>
                      )
                    ) : (
                      <pre className="whitespace-pre-wrap">
{JSON.stringify(blockValue ?? {}, null, 2)}
                      </pre>
                    )
                  ) : (
                    <div className="text-[var(--text-muted)]">No config loaded for this source.</div>
                  )}
                </div>
              </div>
            </div>
            <div className="mt-3 text-xs text-[var(--text-muted)]">
              Select a block to jump to its JSON. Use running for live state, candidate for staged changes.
            </div>
          </Card>

          <Card padding="md">
            <div className="flex flex-wrap items-center gap-2">
              {canEdit && (
                <button
                  onClick={doCommit}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 transition-ui"
                >
                  Commit
                </button>
              )}
              <div className="flex items-center gap-2">
                {canEdit && (
                  <button
                    onClick={doCommitConfirmed}
                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
                  >
                    Commit-confirmed
                  </button>
                )}
                <input
                  value={ttlSeconds}
                  onChange={(e) => setTtlSeconds(e.target.value)}
                  disabled={!canEdit}
                  className="w-20 rounded-md border border-white/[0.08] bg-black/40 px-2 py-1 text-sm text-white transition-ui focus:border-blue-500/40 outline-none"
                />
                <span className="text-xs text-[var(--text)]">seconds</span>
              </div>
              {canEdit && (
                <>
                  <button
                    onClick={doConfirm}
                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
                  >
                    Confirm
                  </button>
                  <button
                    onClick={doRollback}
                    className="rounded-lg bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui"
                  >
                    Rollback
                  </button>
                </>
              )}
            </div>
          </Card>
        </div>
      )}

      {tab === "candidate" && (
        <Card padding="md">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">Candidate JSON</h2>
              <div className="text-xs text-[var(--text-muted)]">
                {candidateLoadedAt
                  ? `Last saved ${candidateLoadedAt.toLocaleString()}`
                  : "Not saved yet"}
              </div>
            </div>
            {canEdit && (
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={copyRunningToCandidate}
                  className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
                >
                  Copy running → candidate
                </button>
                <button
                  onClick={saveCandidate}
                  className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 transition-ui"
                >
                  Save candidate
                </button>
              </div>
            )}
          </div>
          <textarea
            value={candidateText}
            onChange={(e) => setCandidateText(e.target.value)}
            readOnly={!canEdit}
            rows={22}
            className="w-full rounded-lg border border-white/[0.08] bg-black/40 p-3 font-mono text-xs text-white transition-ui focus:border-blue-500/40 outline-none"
          />
        </Card>
      )}

      {tab === "running" && (
        <div className="rounded-xl border border-white/[0.08] bg-black/40 p-4 text-xs text-slate-100 shadow-card">
          <div className="mb-3 flex items-center justify-between text-xs text-slate-400">
            <div>Running config</div>
            <div>{runningLoadedAt ? `Loaded ${runningLoadedAt.toLocaleString()}` : "Not loaded yet"}</div>
          </div>
          <pre>{runningText}</pre>
        </div>
      )}

      {tab === "diff" && (
        <div className="grid gap-4">
          {candidateLoadedAt && runningLoadedAt && candidateLoadedAt < runningLoadedAt && (
            <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 shadow-card">
              Candidate looks older than running. Copy running → candidate to diff your latest changes.
            </div>
          )}
          {!candidate ? (
            <div className="rounded-xl border border-white/[0.08] bg-black/40 p-4 text-sm text-slate-200 shadow-card">
              No candidate config to compare. Save a candidate to see a diff.
            </div>
          ) : diffBlocks.length === 0 ? (
            <div className="rounded-xl border border-white/[0.08] bg-black/40 p-4 text-sm text-slate-200 shadow-card">
              No differences between running and candidate.
            </div>
          ) : (
            diffBlocks.map((block) => (
              <div
                key={block.key}
                className="rounded-xl border border-white/[0.08] bg-black/40 p-4 shadow-card"
              >
                <div className="mb-3 flex items-center justify-between">
                  <div>
                    <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-dim)]">Changed block</div>
                    <div className="text-sm font-semibold text-[var(--text)]">{block.label}</div>
                  </div>
                  <div className="text-xs text-[var(--text-muted)]">
                    {block.diff.filter((l) => l.type === "add").length} added ·{" "}
                    {block.diff.filter((l) => l.type === "del").length} removed
                  </div>
                </div>
                <div className="grid gap-1 rounded-lg border border-white/[0.08] bg-black/60 p-3 text-xs text-slate-100">
                  {block.diff.map((line, idx) => (
                    <div
                      key={`${block.key}-${idx}`}
                      className={
                        line.type === "add"
                          ? "rounded bg-mint/20 px-2 py-0.5 text-mint"
                          : "rounded bg-rose-500/20 px-2 py-0.5 text-rose-200"
                      }
                    >
                      <span className="mr-2 inline-block w-3 text-center">
                        {line.type === "add" ? "+" : "-"}
                      </span>
                      <span className="font-mono">{line.line}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {tab !== "overview" && (
        <Card className="mt-6" padding="md">
          <div className="flex flex-wrap items-center gap-2">
            {canEdit && (
              <button
                onClick={doCommit}
                className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 transition-ui"
              >
                Commit
              </button>
            )}
            <div className="flex items-center gap-2">
              {canEdit && (
                <button
                  onClick={doCommitConfirmed}
                  className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
                >
                  Commit-confirmed
                </button>
              )}
              <input
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(e.target.value)}
                disabled={!canEdit}
                className="w-20 rounded-md border border-white/[0.08] bg-black/40 px-2 py-1 text-sm text-white transition-ui focus:border-blue-500/40 outline-none"
              />
              <span className="text-xs text-slate-300">seconds</span>
            </div>
            {canEdit && (
              <>
                <button
                  onClick={doConfirm}
                  className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-slate-200 hover:bg-white/[0.06] transition-ui"
                >
                  Confirm
                </button>
                <button
                  onClick={doRollback}
                  className="rounded-lg bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui"
                >
                  Rollback
                </button>
              </>
            )}
          </div>
        </Card>
      )}
    </Shell>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2">
      <span className="text-slate-300">{label}</span>
      <span className="text-white">{value}</span>
    </div>
  );
}
