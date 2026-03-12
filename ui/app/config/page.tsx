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
  | "objects"
  | "ids"
  | "services"
  | "dataPlane"
  | "dpi"
  | "export"
  | "pcap";

type DiffLine = { type: "add" | "del" | "same"; line: string };

const TAB_META: Record<Tab, { label: string; description: string }> = {
  overview: { label: "Overview", description: "Backups, restore, and config summary." },
  running: { label: "Live config", description: "What is active on the appliance now." },
  candidate: { label: "Staged config", description: "Saved changes waiting to be reviewed or applied." },
  diff: { label: "Review changes", description: "Compare staged changes against the live config." },
};

const VIEWER_SOURCE_LABEL: Record<ViewerSource, string> = {
  running: "Live",
  candidate: "Staged",
};

function diffLines(aLines: string[], bLines: string[]): DiffLine[] {
  const n = aLines.length;
  const m = bLines.length;
  // Fast path: skip common prefix and suffix to reduce DP matrix size.
  let prefix = 0;
  while (prefix < n && prefix < m && aLines[prefix] === bLines[prefix]) prefix++;
  let suffix = 0;
  while (suffix < n - prefix && suffix < m - prefix && aLines[n - 1 - suffix] === bLines[m - 1 - suffix]) suffix++;
  const aSlice = aLines.slice(prefix, n - suffix);
  const bSlice = bLines.slice(prefix, m - suffix);
  const sn = aSlice.length;
  const sm = bSlice.length;
  // If one side is empty after trimming, fast path.
  if (sn === 0 && sm === 0) {
    return aLines.map((line) => ({ type: "same" as const, line }));
  }
  const prefixLines: DiffLine[] = aLines.slice(0, prefix).map((line) => ({ type: "same" as const, line }));
  const suffixLines: DiffLine[] = aLines.slice(n - suffix).map((line) => ({ type: "same" as const, line }));
  if (sn === 0) {
    return [...prefixLines, ...bSlice.map((line) => ({ type: "add" as const, line })), ...suffixLines];
  }
  if (sm === 0) {
    return [...prefixLines, ...aSlice.map((line) => ({ type: "del" as const, line })), ...suffixLines];
  }
  // Use space-efficient two-row DP instead of full n*m matrix.
  let prev = new Array(sm + 1).fill(0);
  let curr = new Array(sm + 1).fill(0);
  for (let i = 1; i <= sn; i += 1) {
    for (let j = 1; j <= sm; j += 1) {
      if (aSlice[i - 1] === bSlice[j - 1]) curr[j] = prev[j - 1] + 1;
      else curr[j] = Math.max(prev[j], curr[j - 1]);
    }
    [prev, curr] = [curr, prev];
    curr.fill(0);
  }
  // Backtrack needs full matrix — but only for the trimmed portion which is much smaller.
  const dp: number[][] = Array.from({ length: sn + 1 }, () => new Array(sm + 1).fill(0));
  for (let i = 1; i <= sn; i += 1) {
    for (let j = 1; j <= sm; j += 1) {
      if (aSlice[i - 1] === bSlice[j - 1]) dp[i][j] = dp[i - 1][j - 1] + 1;
      else dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  const mid: DiffLine[] = [];
  let i = sn;
  let j = sm;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && aSlice[i - 1] === bSlice[j - 1]) {
      mid.push({ type: "same", line: aSlice[i - 1] });
      i -= 1;
      j -= 1;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      mid.push({ type: "add", line: bSlice[j - 1] });
      j -= 1;
    } else if (i > 0) {
      mid.push({ type: "del", line: aSlice[i - 1] });
      i -= 1;
    }
  }
  mid.reverse();
  return [...prefixLines, ...mid, ...suffixLines];
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
      setStatus(statusWithWarning("Candidate saved.", res.warning));
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
    setStatus(statusWithWarning("Candidate replaced with running.", res.warning));
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
          window.dispatchEvent(new CustomEvent("containd:config:committed"));
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
          window.dispatchEvent(new CustomEvent("containd:config:committed"));
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
      setStatus(res.ok ? statusWithWarning("Config restored.", res.warning) : `Restore failed: ${res.error}`);
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
      { key: "objects", label: "Objects", running: (r as any).objects, candidate: (c as any).objects },
      { key: "ids", label: "IDS", running: (r as any).ids, candidate: (c as any).ids },
      { key: "services", label: "Services", running: (r as any).services, candidate: (c as any).services },
      { key: "dataPlane", label: "Data plane", running: (r as any).dataplane, candidate: (c as any).dataplane },
      { key: "dpi", label: "DPI", running: { dpiMode: (r as any).dataplane?.dpiMode, dpiIcsProtocols: (r as any).dataplane?.dpiIcsProtocols, dpiProtocols: (r as any).dataplane?.dpiProtocols, dpiEnabled: (r as any).dataplane?.dpiEnabled, dpiExclusions: (r as any).dataplane?.dpiExclusions }, candidate: { dpiMode: (c as any).dataplane?.dpiMode, dpiIcsProtocols: (c as any).dataplane?.dpiIcsProtocols, dpiProtocols: (c as any).dataplane?.dpiProtocols, dpiEnabled: (c as any).dataplane?.dpiEnabled, dpiExclusions: (c as any).dataplane?.dpiExclusions } },
      { key: "export", label: "Export", running: (r as any).export, candidate: (c as any).export },
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
      case "objects":
        return (cfg.objects ?? []).map((o: any): BlockItem => ({
          id: String(o.id || o.name),
          label: String(o.name || o.id),
          meta: o.type || "Object",
        }));
      case "ids":
        return (cfg.ids?.rules ?? []).map((r: any): BlockItem => ({
          id: String(r.id || r.title),
          label: String(r.title || r.id),
          meta: r.severity || "Rule",
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
      case "objects":
        return (cfg.objects ?? []).find(
          (o: any) => (o.id || o.name) === selectedItemId,
        ) ?? null;
      case "ids":
        return (cfg.ids?.rules ?? []).find(
          (r: any) => (r.id || r.title) === selectedItemId,
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
      case "objects":
        return cfg.objects;
      case "ids":
        return cfg.ids;
      case "services":
        return cfg.services;
      case "dataPlane":
        return cfg.dataplane;
      case "dpi":
        return { dpiMode: cfg.dataplane?.dpiMode, dpiEnabled: cfg.dataplane?.dpiEnabled, dpiIcsProtocols: cfg.dataplane?.dpiIcsProtocols, dpiProtocols: cfg.dataplane?.dpiProtocols, dpiExclusions: cfg.dataplane?.dpiExclusions };
      case "export":
        return cfg.export;
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
  const idsRuleCount = (running as any)?.ids?.rules?.length ?? 0;
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
      body: "Restore replaces the live config; use commit-confirmed if you need a safe rollback window.",
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
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
        >
          Refresh
        </button>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
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
                ? "rounded-sm bg-amber-500/[0.1] px-3 py-1.5 text-sm text-[var(--text)] transition-ui"
                : "rounded-sm px-3 py-1.5 text-sm text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
            }
          >
            {TAB_META[t].label}
          </button>
        ))}
      </div>
      <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-xs text-[var(--text)]">
        Workflow: edit the staged config, review the change summary, then commit or commit-confirmed to update the live appliance safely.
      </div>

      {status && (
        <div
          className={`mb-4 rounded-sm px-4 py-3 text-sm ${
            status.includes("failed") || status.includes("Failed") || status === "Invalid JSON." || status === "Invalid JSON file."
              ? "border border-red-500/30 bg-red-500/10 text-red-400"
              : status.includes("saved") || status.includes("Committed") || status.includes("confirmed") || status.includes("restored") || status.includes("downloaded") || status.includes("deleted") || status.includes("Rolled back") || status.includes("replaced")
                ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                : "border border-amber-500/[0.15] bg-[var(--surface)] text-[var(--text)]"
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
                  <h2 className="text-lg font-semibold text-[var(--text)]">Backup &amp; recovery</h2>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => downloadConfig(true)}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                  >
                    Download redacted
                  </button>
                  {canEdit && (
                    <button
                      onClick={() => downloadConfig(false)}
                      className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
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
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
                />
                <div className="text-xs text-[var(--text-muted)]">
                  Restore replaces the live config. Use redacted backups for sharing.
                </div>
                {canEdit && (
                  <button
                    onClick={restoreConfig}
                    className="rounded-sm bg-[var(--amber)] px-3 py-2 text-sm font-medium text-white hover:brightness-110 transition-ui"
                  >
                    Restore
                  </button>
                )}
              </div>
              <div className="mt-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 shadow-card">
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
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                  >
                    Save redacted
                  </button>
                  {canEdit && (
                      <button
                        onClick={() => createBackup(false)}
                        className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white hover:brightness-110 transition-ui"
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
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
                  />
                  <div className="text-xs text-[var(--text-muted)]">
                    Backups are stored under the appliance data volume.
                  </div>
                </div>
                <div className="mt-3 grid gap-2">
                  {backups.length === 0 ? (
                    <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text-muted)]">
                      No backups saved yet.
                    </div>
                  ) : (
                    backups.map((backup) => (
                      <div
                        key={backup.id}
                        className="grid gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:grid-cols-[1fr_auto]"
                      >
                        <div>
                          <div className="font-semibold text-[var(--text)]">{backup.name}</div>
                          <div className="text-[11px] text-[var(--text-muted)]">
                            {new Date(backup.createdAt).toLocaleString()} · {formatBytes(backup.size)} ·{" "}
                            {backup.redacted ? "Redacted" : "Full"}
                            {backup.idsRuleCount ? ` · ${backup.idsRuleCount} IDS rules` : ""} · ID {backup.id.slice(0, 6)}
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center justify-end gap-2">
                          <button
                            onClick={() => downloadBackup(backup)}
                            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
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
              <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                Config summary
              </div>
              <div className="mt-3 grid gap-3 text-sm">
                <Stat label="Zones" value={zoneCount} />
                <Stat label="Interfaces" value={ifaceCount} />
                <Stat label="Firewall rules" value={ruleCount} />
                <Stat label="Assets" value={assetCount} />
                <Stat label="Objects" value={objectCount} />
                <Stat label="IDS rules" value={idsRuleCount} />
                <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2">
                  <span className="text-[var(--text)]">DPI mode</span>
                  <span className={dpiMode === "enforce" ? "text-emerald-400" : dpiMode === "learn" ? "text-amber-400" : "text-[var(--text-muted)]"}>{dpiMode}</span>
                </div>
              </div>
              <div className="mt-4 text-xs text-[var(--text-muted)]">
                Typical workflow: define zones, bind interfaces, add policy, review changes, then commit.
              </div>
            </Card>
          </div>

          <Card padding="md">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">IDS Rules</div>
                <div className="text-sm text-[var(--text)]">
                  IDS rules are stored separately from the config ({idsRuleCount} rules loaded).
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={async () => {
                    setStatus(null);
                    const blob = await api.backupIDSRules();
                    if (!blob) { setStatus("Failed to export IDS rules."); return; }
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = "containd-ids-rules.json";
                    a.click();
                    URL.revokeObjectURL(url);
                    setStatus("IDS rules downloaded.");
                  }}
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                >
                  Download rules
                </button>
                {canEdit && (
                  <label className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui cursor-pointer">
                    Restore rules
                    <input
                      type="file"
                      accept=".json"
                      className="hidden"
                      onChange={async (e) => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        setStatus(null);
                        try {
                          const text = await file.text();
                          const rules = JSON.parse(text);
                          if (!Array.isArray(rules)) { setStatus("Invalid IDS rules file (expected JSON array)."); return; }
                          const res = await api.restoreIDSRules(rules);
                          setStatus(res.ok ? `Restored ${res.data.count} IDS rules.` : `Restore failed: ${res.error}`);
                          refresh();
                        } catch {
                          setStatus("Invalid JSON file.");
                        }
                        e.target.value = "";
                      }}
                    />
                  </label>
                )}
              </div>
            </div>
          </Card>

          <Card padding="lg">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                  Config viewer
                </div>
                <h2 className="text-lg font-semibold text-[var(--text)]">Explore config blocks</h2>
              </div>
              <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
                <span>Source</span>
                <button
                  onClick={() => setViewerSource("running")}
                  className={
                    viewerSource === "running"
                      ? "rounded-md bg-amber-500/[0.1] px-2 py-1 text-[var(--text)] transition-ui"
                      : "rounded-md px-2 py-1 text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
                  }
                >
                  {VIEWER_SOURCE_LABEL.running}
                </button>
                <button
                  onClick={() => setViewerSource("candidate")}
                  className={
                    viewerSource === "candidate"
                      ? "rounded-md bg-amber-500/[0.1] px-2 py-1 text-[var(--text)] transition-ui"
                      : "rounded-md px-2 py-1 text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
                  }
                >
                  {VIEWER_SOURCE_LABEL.candidate}
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
                    { key: "objects", label: "Objects", help: "Named address/service objects for reuse in rules." },
                    { key: "ids", label: "IDS", help: "Detection rules, Sigma/YARA imports, and settings." },
                    { key: "services", label: "Services", help: "DNS, NTP, DHCP, proxy, VPN, AV, and syslog." },
                    { key: "dataPlane", label: "Data plane", help: "Enforcement, capture interfaces, nftables." },
                    { key: "dpi", label: "DPI", help: "DPI mode (learn/enforce), protocol enable/disable, exclusions." },
                    { key: "export", label: "Export", help: "Event export targets (CEF, JSON, Syslog)." },
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
                        ? "rounded-sm bg-amber-500/[0.1] px-3 py-2 text-left text-sm text-[var(--text)] transition-ui"
                        : "rounded-sm px-3 py-2 text-left text-sm text-[var(--text-muted)] hover:text-[var(--text)] hover:bg-amber-500/[0.04] transition-ui"
                    }
                  >
                    {item.label}
                  </button>
                ))}
              </div>
              <div className="grid gap-3">
                {blockItems.length > 0 && (
                  <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 shadow-card">
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
                              ? "rounded-sm border border-amber-500/[0.15] bg-amber-500/[0.1] px-2 py-1 text-left text-xs text-[var(--text)] transition-ui"
                              : "rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-left text-xs text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                          }
                        >
                          <div className="font-semibold">{item.label}</div>
                          <div className="text-[11px] text-[var(--text-muted)]">{item.meta}</div>
                        </button>
                      ))}
                    </div>
                    {selectedItem && (
                      <div className="mt-3 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 text-xs text-[var(--text)]">
                        <div className="mb-2 flex items-center justify-between">
                          <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                            Selected
                          </div>
                          {selectedBlock === "zones" && (
                            <a href="/zones/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                              Open Zones
                            </a>
                          )}
                          {selectedBlock === "interfaces" && (
                            <a href="/interfaces/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                              Open Interfaces
                            </a>
                          )}
                          {selectedBlock === "firewall" && (
                            <a href="/firewall/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                              Open Firewall
                            </a>
                          )}
                          {selectedBlock === "assets" && (
                            <a href="/assets/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                              Open Assets
                            </a>
                          )}
                          {selectedBlock === "ids" && (
                            <a href="/ids/" className="text-xs text-[var(--amber)] hover:text-[var(--amber)] transition-ui">
                              Open IDS
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
                <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 text-xs text-[var(--text)]">
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
                                    ? "rounded-sm border border-amber-500/40 bg-amber-500/[0.1] p-3 transition-ui"
                                    : "rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 hover:border-amber-500/30 transition-ui"
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
              Select a block to jump to its JSON. Use Live for current runtime state and Staged for saved changes waiting to be applied.
            </div>
          </Card>

          <Card padding="md">
            <div className="flex flex-wrap items-center gap-2">
              {canEdit && (
                <button
                  onClick={doCommit}
                  className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
                >
                  Commit
                </button>
              )}
              <div className="flex items-center gap-2">
                {canEdit && (
                  <button
                    onClick={doCommitConfirmed}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                  >
                    Commit-confirmed
                  </button>
                )}
                <input
                  value={ttlSeconds}
                  onChange={(e) => setTtlSeconds(e.target.value)}
                  disabled={!canEdit}
                  className="w-20 rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
                />
                <span className="text-xs text-[var(--text)]">seconds</span>
              </div>
              {canEdit && (
                <>
                  <button
                    onClick={doConfirm}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                  >
                    Confirm
                  </button>
                  <button
                    onClick={doRollback}
                    className="rounded-sm bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui"
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
              <h2 className="text-sm font-semibold text-[var(--text)]">Staged config JSON</h2>
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
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                >
                  Copy live → staged
                </button>
                <button
                  onClick={saveCandidate}
                  className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
                >
                  Save staged config
                </button>
              </div>
            )}
          </div>
          <div className="mb-3 text-xs text-[var(--text-muted)]">
            Changes here are saved but not active until you review and commit them.
          </div>
          <textarea
            value={candidateText}
            onChange={(e) => setCandidateText(e.target.value)}
            readOnly={!canEdit}
            rows={22}
            className="w-full rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 font-mono text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
          />
        </Card>
      )}

      {tab === "running" && (
        <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 text-xs text-[var(--text)] shadow-card">
          <div className="mb-3 flex items-center justify-between text-xs text-[var(--text-muted)]">
            <div>Live config</div>
            <div>{runningLoadedAt ? `Loaded ${runningLoadedAt.toLocaleString()}` : "Not loaded yet"}</div>
          </div>
          <div className="mb-3 text-xs text-[var(--text-muted)]">
            This is the config currently applied on the appliance.
          </div>
          <pre>{runningText}</pre>
        </div>
      )}

      {tab === "diff" && (
        <div className="grid gap-4">
          {candidateLoadedAt && runningLoadedAt && candidateLoadedAt < runningLoadedAt && (
            <div className="rounded-sm border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400 shadow-card">
              Staged config looks older than live config. Copy live → staged first if you want to review your latest active state.
            </div>
          )}
          {!candidate ? (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 text-sm text-[var(--text)] shadow-card">
              No staged config to compare. Save staged changes to review them here.
            </div>
          ) : diffBlocks.length === 0 ? (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 text-sm text-[var(--text)] shadow-card">
              No differences between live and staged config.
            </div>
          ) : (
            diffBlocks.map((block) => (
              <div
                key={block.key}
                className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 shadow-card"
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
                <div className="grid gap-1 rounded-sm border border-amber-500/[0.15] bg-black/60 p-3 text-xs text-[var(--text)]">
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
                className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
              >
                Commit
              </button>
            )}
            <div className="flex items-center gap-2">
              {canEdit && (
                <button
                  onClick={doCommitConfirmed}
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                >
                  Commit-confirmed
                </button>
              )}
              <input
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(e.target.value)}
                disabled={!canEdit}
                className="w-20 rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
              />
              <span className="text-xs text-[var(--text)]">seconds</span>
            </div>
            {canEdit && (
              <>
                <button
                  onClick={doConfirm}
                  className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                >
                  Confirm
                </button>
                <button
                  onClick={doRollback}
                  className="rounded-sm bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui"
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
    <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2">
      <span className="text-[var(--text)]">{label}</span>
      <span className="text-[var(--text)]">{value}</span>
    </div>
  );
}
