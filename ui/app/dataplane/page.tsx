"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  api,
  isAdmin,
  deletePcap,
  downloadPcapURL,
  getPcapConfig,
  getPcapStatus,
  listPcaps,
  replayPcap,
  uploadPcap,
  setPcapConfig,
  startPcap,
  stopPcap,
  tagPcap,
  type Interface,
  type InterfaceState,
  type PcapConfig,
  type PcapForwardTarget,
  type PcapItem,
  type PcapStatus,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { InfoTip } from "../../components/InfoTip";
import { Card } from "../../components/Card";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";

type CaptureMode = "once" | "rolling";
type SaveState = "idle" | "starting" | "stopping";

type PcapForwardRow = PcapForwardTarget & { interface: string };

export default function PcapPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const [ifaces, setIfaces] = useState<Interface[]>([]);
  const [ifaceStates, setIfaceStates] = useState<InterfaceState[]>([]);
  const [state, setState] = useState<SaveState>("idle");
  const [notice, setNotice] = useState<string | null>(null);
  const [status, setStatus] = useState<PcapStatus | null>(null);
  const [pcaps, setPcaps] = useState<PcapItem[]>([]);
  const [pcapQuery, setPcapQuery] = useState("");
  const [pcapTag, setPcapTag] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [ifaceFilter, setIfaceFilter] = useState<string>("all");
  const [replayName, setReplayName] = useState("");
  const [replayIface, setReplayIface] = useState("");
  const [replayRate, setReplayRate] = useState("");
  const [uploading, setUploading] = useState(false);
  const uploadInputRef = useRef<HTMLInputElement | null>(null);
  const [savedConfigJson, setSavedConfigJson] = useState<string | null>(null);
  const dirtyRef = useRef(false);
  const [settings, setSettings] = useState<PcapConfig>({
    enabled: false,
    interfaces: [],
    snaplen: 262144,
    maxSizeMB: 64,
    maxFiles: 8,
    mode: "rolling",
    promisc: true,
    bufferMB: 4,
    rotateSeconds: 300,
    filePrefix: "capture",
    filter: { src: "", dst: "", proto: "any" },
    forwardTargets: [],
  });

  const settingsSnapshot = useMemo(
    () => JSON.stringify(normalizeConfig(settings)),
    [settings],
  );
  const isDirty = savedConfigJson ? settingsSnapshot !== savedConfigJson : false;
  useEffect(() => {
    dirtyRef.current = isDirty;
  }, [isDirty]);

  async function refresh() {
    setRefreshing(true);
    const [cfg, st, list] = await Promise.all([
      getPcapConfig(),
      getPcapStatus(),
      listPcaps(),
    ]);
    if (cfg) {
      const normalized = normalizeConfig(cfg);
      const nextJson = JSON.stringify(normalized);
      if (!dirtyRef.current) {
        setSettings(normalized);
      }
      setSavedConfigJson(nextJson);
    }
    setStatus(st);
    setPcaps(list);
    setLastRefresh(new Date());
    setRefreshing(false);
  }

  useEffect(() => {
    api.listInterfaces().then((list) => setIfaces(list ?? []));
    api.listInterfaceState().then((list) => setIfaceStates(list ?? []));
  }, []);
  useEffect(() => {
    refresh();
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      refresh();
    }, 8000);
    return () => clearInterval(timer);
  }, []);

  const ifaceOptions = useMemo(() => {
    const options = new Map<string, string>();
    const osSet = new Set((ifaceStates ?? []).map((s) => s.name));
    for (const iface of ifaces ?? []) {
      const device = iface.device?.trim();
      const alias = iface.alias?.trim();
      const bound = !!device || osSet.has(iface.name);
      if (!bound) continue;
      const value = device || iface.name;
      if (!value) continue;
      const baseLabel = device ? `${iface.name} (${device})` : iface.name;
      const label = alias ? `${alias} (${baseLabel})` : baseLabel;
      options.set(value, label);
    }
    return Array.from(options.entries()).map(([value, label]) => ({ value, label }));
  }, [ifaces, ifaceStates]);

  useEffect(() => {
    setSettings((prev) => {
      const existing = new Map((prev.forwardTargets ?? []).map((t) => [t.interface ?? "", t]));
      const next = ifaceOptions.map((iface) => {
        const current = existing.get(iface.value);
        return (
          current ?? {
            interface: iface.value,
            enabled: false,
            host: "",
            port: 9000,
            proto: "udp" as const,
          }
        );
      });
      return { ...prev, forwardTargets: next };
    });
  }, [ifaceOptions]);

  const bpfPreview = useMemo(() => {
    const clauses: string[] = [];
    const filter = settings.filter ?? {};
    if (filter.proto && filter.proto !== "any") clauses.push(filter.proto);
    if (filter.src?.trim()) clauses.push(`src host ${filter.src.trim()}`);
    if (filter.dst?.trim()) clauses.push(`dst host ${filter.dst.trim()}`);
    return clauses.length ? clauses.join(" and ") : "not set";
  }, [settings.filter]);
  const configIssues = useMemo(() => {
    const issues: string[] = [];
    if ((settings.interfaces ?? []).length === 0) issues.push("Select at least one interface to capture.");
    if (ifaceOptions.length === 0) {
      issues.push("No firewall interfaces are bound to OS devices. Set device bindings on the Interfaces page.");
    }
    if (ifaceStates.length > 0) {
      const available = new Set(ifaceStates.map((i) => i.name));
      const missing = (settings.interfaces ?? []).filter((name) => !available.has(name));
      if (missing.length > 0) {
        issues.push(`Interfaces not found in OS: ${missing.join(", ")}. Bind to a device in Interfaces or select a kernel interface.`);
      }
    }
    if (!Number.isFinite(settings.snaplen) || (settings.snaplen ?? 0) <= 0) issues.push("Snaplen must be greater than 0.");
    if (!Number.isFinite(settings.maxSizeMB) || (settings.maxSizeMB ?? 0) <= 0) issues.push("Max size must be greater than 0.");
    if (!Number.isFinite(settings.maxFiles) || (settings.maxFiles ?? 0) <= 0) issues.push("Max files must be greater than 0.");
    if (!Number.isFinite(settings.bufferMB) || (settings.bufferMB ?? 0) <= 0) issues.push("Buffer must be greater than 0.");
    if (!Number.isFinite(settings.rotateSeconds) || (settings.rotateSeconds ?? 0) < 0) issues.push("Rotate interval must be 0 or greater.");
    const badForward = (settings.forwardTargets ?? []).filter(
      (t) => t.enabled && (!(t.host ?? "").trim() || !Number.isFinite(t.port) || (t.port ?? 0) <= 0),
    );
    if (badForward.length > 0) issues.push("Forwarding targets need a host and valid port when enabled.");
    return issues;
  }, [settings, ifaceStates, ifaceOptions.length]);
  const isRunning = status?.running ?? settings.enabled ?? false;
  const canStart = canEdit && configIssues.length === 0 && state === "idle" && !isRunning;
  const captureSummary = useMemo(() => {
    const ifaceLabel = (settings.interfaces ?? []).length ? (settings.interfaces ?? []).join(", ") : "no interfaces";
    const rotation =
      settings.mode === "rolling"
        ? `${settings.maxFiles ?? 0} files @ ${settings.maxSizeMB ?? 0}MB`
        : `${settings.maxSizeMB ?? 0}MB max`;
    return `${ifaceLabel} · ${rotation} · snaplen ${settings.snaplen ?? 0}`;
  }, [settings.interfaces, settings.mode, settings.maxFiles, settings.maxSizeMB, settings.snaplen]);
  const filteredPcaps = useMemo(() => {
    const q = pcapQuery.trim().toLowerCase();
    if (!q) return pcaps;
    return pcaps.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.interface.toLowerCase().includes(q) ||
        (p.tags ?? []).some((t) => t.toLowerCase().includes(q)),
    );
  }, [pcaps, pcapQuery]);
  const visiblePcaps = useMemo(() => {
    if (ifaceFilter === "all") return filteredPcaps;
    return filteredPcaps.filter((p) => p.interface === ifaceFilter);
  }, [filteredPcaps, ifaceFilter]);
  const totalSizeMB = useMemo(() => {
    if (!pcaps.length) return 0;
    const bytes = pcaps.reduce((sum, p) => sum + (p.sizeBytes ?? 0), 0);
    return bytes / (1024 * 1024);
  }, [pcaps]);
  const ifaceStats = useMemo(() => {
    const stats = new Map<string, { count: number; sizeBytes: number }>();
    for (const p of pcaps) {
      const key = p.interface || "unknown";
      const current = stats.get(key) ?? { count: 0, sizeBytes: 0 };
      current.count += 1;
      current.sizeBytes += p.sizeBytes ?? 0;
      stats.set(key, current);
    }
    return Array.from(stats.entries()).sort((a, b) => b[1].count - a[1].count);
  }, [pcaps]);
  const enabledForwarding = useMemo(() => {
    return (settings.forwardTargets ?? [])
      .filter((t) => t.enabled && t.host)
      .map((t) => `${t.interface} → ${t.host}:${t.port ?? ""}`.trim());
  }, [settings.forwardTargets]);
  const runningSince = useMemo(() => {
    if (!status?.startedAt) return "—";
    const started = new Date(status.startedAt);
    if (Number.isNaN(started.getTime())) return "—";
    return started.toLocaleString();
  }, [status?.startedAt]);

  async function addTag(pcapName: string) {
    const tag = pcapTag.trim();
    if (!tag) return;
    const item = pcaps.find((p) => p.name === pcapName);
    const tags = Array.from(new Set([...(item?.tags ?? []), tag]));
    const ok = await tagPcap({ name: pcapName, tags });
    if (ok) {
      setPcapTag("");
      const list = await listPcaps();
      setPcaps(list);
    } else {
      setNotice("Failed to update PCAP tags.");
    }
  }

  function toggleIface(name: string) {
    setSettings((prev) => {
      const set = new Set(prev.interfaces ?? []);
      if (set.has(name)) set.delete(name);
      else set.add(name);
      return { ...prev, interfaces: Array.from(set) };
    });
  }

  function setAllInterfaces(on: boolean) {
    setSettings((prev) => ({
      ...prev,
      interfaces: on ? ifaceOptions.map((opt) => opt.value) : [],
    }));
  }

  function updateForwardTarget(iface: string, patch: Partial<PcapForwardRow>) {
    setSettings((prev) => ({
      ...prev,
      forwardTargets: (prev.forwardTargets ?? []).map((t) =>
        t.interface === iface ? { ...t, ...patch } : t,
      ),
    }));
  }

  async function startCapture() {
    if (!canEdit) return;
    if (configIssues.length > 0) {
      setNotice("Fix capture settings before starting.");
      return;
    }
    setState("starting");
    const saved = await setPcapConfig(settings);
    if (!saved) {
      setNotice("Failed to save capture settings.");
      setState("idle");
      return;
    }
    setSavedConfigJson(JSON.stringify(normalizeConfig(saved)));
    const st = await startPcap(saved);
    if (!st) {
      setNotice("Failed to start capture.");
    } else {
      setStatus(st);
      setSettings((prev) => ({ ...prev, enabled: true }));
    }
    setState("idle");
    await refresh();
  }

  async function stopCapture() {
    if (!canEdit) return;
    setState("stopping");
    const st = await stopPcap();
    if (!st) {
      setNotice("Failed to stop capture.");
    } else {
      setStatus(st);
      setSettings((prev) => ({ ...prev, enabled: false }));
    }
    setState("idle");
    await refresh();
  }

  async function saveSettings() {
    if (!canEdit) return;
    if (configIssues.length > 0) {
      setNotice("Fix capture settings before saving.");
      return;
    }
    const saved = await setPcapConfig(settings);
    if (!saved) {
      setNotice("Failed to save capture settings.");
      return;
    }
    setSettings(normalizeConfig(saved));
    setSavedConfigJson(JSON.stringify(normalizeConfig(saved)));
    setNotice("Capture settings saved.");
    await refresh();
  }

  async function handleUpload(file: File | null) {
    if (!file || !canEdit) return;
    if (!file.name.toLowerCase().endsWith(".pcap")) {
      setNotice("Only .pcap files are supported for upload.");
      return;
    }
    setUploading(true);
    const item = await uploadPcap(file);
    if (!item) {
      setNotice("Failed to upload PCAP.");
    } else {
      await refresh();
    }
    if (uploadInputRef.current) {
      uploadInputRef.current.value = "";
    }
    setUploading(false);
  }

  return (
    <Shell
      title="PCAP"
      actions={
        <div className="flex items-center gap-2">
          {canEdit ? (
            <>
              <button
                onClick={saveSettings}
                disabled={state !== "idle"}
                className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
              >
                Save settings
              </button>
              <button
                onClick={startCapture}
                disabled={!canStart}
                className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui disabled:opacity-50"
              >
                {state === "starting" ? "Starting..." : "Start capture"}
              </button>
              <button
                onClick={stopCapture}
                disabled={state !== "idle" || !isRunning}
                className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
              >
                {state === "stopping" ? "Stopping..." : "Stop"}
              </button>
            </>
          ) : (
            <span className="text-xs text-[var(--text-muted)]">View-only</span>
          )}
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {notice && (
        <div className="mb-4 rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
          {notice}
        </div>
      )}
      <Card className="mb-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-[var(--text)]">Capture Status</div>
            <div className="mt-1 text-sm text-[var(--text)]">
              {isRunning ? "Running" : "Stopped"}
            </div>
          </div>
          <span className={`rounded-full px-2 py-0.5 text-xs ${isRunning ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/[0.1] text-[var(--text)]"}`}>
            {isRunning ? "active" : "idle"}
          </span>
        </div>
        <div className="mt-2 text-xs text-[var(--text-muted)]">{captureSummary}</div>
        <div className="mt-2 text-xs text-[var(--text-muted)]">
          Started: <span className="text-[var(--text)]">{runningSince}</span>
        </div>
        <div className="mt-1 text-xs text-[var(--text-muted)]">
          Active interfaces:{" "}
          <span className="text-[var(--text)]">
            {(status?.interfaces ?? settings.interfaces ?? []).length
              ? (status?.interfaces ?? settings.interfaces ?? []).join(", ")
              : "none"}
          </span>
        </div>
        {status?.lastError ? (
          <div className="mt-2 rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
            {status.lastError}
          </div>
        ) : null}
      </Card>
      <Card padding="lg">
        <h2 className="text-lg font-semibold text-[var(--text)]">Capture setup</h2>
        <p className="mt-1 text-sm text-[var(--text)]">
          Start/stop packet captures on selected interfaces and store PCAPs for replay.
        </p>
        {configIssues.length > 0 && (
          <div className="mt-3 rounded-sm border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-400">
            <div className="font-semibold">Capture checks</div>
            <ul className="mt-1 list-disc space-y-0.5 pl-4">
              {configIssues.map((issue) => (
                <li key={issue}>{issue}</li>
              ))}
            </ul>
          </div>
        )}

        <div className="mt-4 grid gap-4">
          <div>
            <div className="flex items-center justify-between text-xs uppercase tracking-wide text-[var(--text-muted)]">
              <span>Interfaces</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setAllInterfaces(true)}
                  disabled={!canEdit}
                  className="rounded-full border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-0.5 text-[10px] text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
                >
                  All
                </button>
                <button
                  onClick={() => setAllInterfaces(false)}
                  disabled={!canEdit}
                  className="rounded-full border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-0.5 text-[10px] text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
                >
                  None
                </button>
              </div>
            </div>
            <div className="mt-2 grid gap-2 md:grid-cols-4">
              {ifaceOptions.map((opt) => (
                <label key={opt.value} className="flex items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui">
                  <input
                    type="checkbox"
                    checked={(settings.interfaces ?? []).includes(opt.value)}
                    disabled={!canEdit}
                    onChange={() => toggleIface(opt.value)}
                    className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Mode
                <InfoTip label="Rolling keeps the newest files; Once stops after max size." />
              </label>
              <select
                value={settings.mode}
                disabled={!canEdit}
                onChange={(e) => setSettings((prev) => ({ ...prev, mode: e.target.value as CaptureMode }))}
                className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              >
                <option value="rolling">rolling</option>
                <option value="once">once</option>
              </select>
            </div>
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Snaplen (bytes)
                <InfoTip label="Max bytes captured per packet (higher = larger PCAPs)." />
              </label>
              <input
                type="number"
                value={settings.snaplen}
                disabled={!canEdit}
                onChange={(e) => setSettings((prev) => ({ ...prev, snaplen: Number(e.target.value) || 0 }))}
                className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Max size (MB)
                <InfoTip label="Max file size before rotation or stop." />
              </label>
              <input
                type="number"
                value={settings.maxSizeMB}
                disabled={!canEdit}
                onChange={(e) => setSettings((prev) => ({ ...prev, maxSizeMB: Number(e.target.value) || 0 }))}
                className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
          </div>

          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                Max files
                <InfoTip label="How many files to keep when in rolling mode." />
              </label>
              <input
                type="number"
                value={settings.maxFiles}
                disabled={!canEdit}
                onChange={(e) => setSettings((prev) => ({ ...prev, maxFiles: Number(e.target.value) || 0 }))}
                className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <div className="md:col-span-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3">
              <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">Filters (tcpdump style)</div>
              <div className="mt-2 grid gap-2 md:grid-cols-3">
                <input
                  value={settings.filter?.src ?? ""}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setSettings((prev) => ({ ...prev, filter: { ...(prev.filter ?? {}), src: e.target.value } }))
                  }
                  placeholder="src host 10.0.0.10"
                  className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  value={settings.filter?.dst ?? ""}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setSettings((prev) => ({ ...prev, filter: { ...(prev.filter ?? {}), dst: e.target.value } }))
                  }
                  placeholder="dst host 10.0.0.20"
                  className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <select
                  value={settings.filter?.proto ?? "any"}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setSettings((prev) => ({
                      ...prev,
                      filter: { ...(prev.filter ?? {}), proto: e.target.value as "any" | "tcp" | "udp" | "icmp" },
                    }))
                  }
                  className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                >
                  <option value="any">any proto</option>
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                  <option value="icmp">icmp</option>
                </select>
              </div>
              <div className="mt-2 text-xs text-[var(--text-muted)]">
                Filter preview: <span className="font-mono text-[var(--text)]">{bpfPreview}</span>
              </div>
            </div>
          </div>

          <details className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
            <summary className="cursor-pointer text-sm text-[var(--text)]">Advanced capture options</summary>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  File prefix
                  <InfoTip label="Prefix for saved PCAP files." />
                </label>
                <input
                  value={settings.filePrefix}
                  disabled={!canEdit}
                  onChange={(e) => setSettings((prev) => ({ ...prev, filePrefix: e.target.value }))}
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Rotate interval (seconds)
                  <InfoTip label="Rotate files on time in addition to size." />
                </label>
                <input
                  type="number"
                  value={settings.rotateSeconds}
                  disabled={!canEdit}
                  onChange={(e) => setSettings((prev) => ({ ...prev, rotateSeconds: Number(e.target.value) || 0 }))}
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Buffer (MB)
                  <InfoTip label="Capture buffer size before flush." />
                </label>
                <input
                  type="number"
                  value={settings.bufferMB}
                  disabled={!canEdit}
                  onChange={(e) => setSettings((prev) => ({ ...prev, bufferMB: Number(e.target.value) || 0 }))}
                  className="mt-1 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <label className="flex items-center gap-2 text-sm text-[var(--text)]">
                <input
                  type="checkbox"
                  checked={settings.promisc}
                  disabled={!canEdit}
                  onChange={(e) => setSettings((prev) => ({ ...prev, promisc: e.target.checked }))}
                  className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
                />
                Promiscuous mode
                <InfoTip label="Capture all traffic seen by the interface." />
              </label>
            </div>
          </details>

          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">PCAP Forwarding (Remote Sensor)</div>
                <p className="mt-1 text-sm text-[var(--text)]">
                  Stream captures per interface to a remote sensor (tap-style).
                </p>
              </div>
            </div>
            <div className="mt-3 grid gap-2 text-[11px] uppercase tracking-wide text-[var(--text-dim)] md:grid-cols-[120px_1fr_120px_120px]">
              <span>Interface</span>
              <span>Sensor Host</span>
              <span>Port</span>
              <span>Proto</span>
            </div>
            <div className="mt-3 grid gap-2">
              {(settings.forwardTargets ?? []).map((target) => {
                if (!target.interface) return null;
                const iface = target.interface;
                return (
                <div
                  key={iface}
                  className="grid gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 md:grid-cols-[120px_1fr_120px_120px]"
                >
                  <label className="flex items-center gap-2 text-sm text-[var(--text)]">
                    <input
                      type="checkbox"
                      checked={target.enabled}
                      disabled={!canEdit}
                      onChange={(e) => updateForwardTarget(iface, { enabled: e.target.checked })}
                      className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
                    />
                    {iface}
                  </label>
                  <input
                    value={target.host}
                    disabled={!canEdit || !target.enabled}
                    onChange={(e) => updateForwardTarget(iface, { host: e.target.value })}
                    placeholder="sensor.example.local"
                    className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
                  />
                  <input
                    type="number"
                    value={target.port}
                    disabled={!canEdit || !target.enabled}
                    onChange={(e) => updateForwardTarget(iface, { port: Number(e.target.value) || 0 })}
                    className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
                  />
                  <select
                    value={target.proto}
                    disabled={!canEdit || !target.enabled}
                    onChange={(e) => updateForwardTarget(iface, { proto: e.target.value as "tcp" | "udp" })}
                    className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-60"
                  />
                </div>
                );
              })}
            </div>
            <div className="mt-2 text-xs text-[var(--text-muted)]">
              Streams PCAP data to remote collectors; configure one target per interface.
            </div>
            {enabledForwarding.length > 0 ? (
              <div className="mt-2 text-xs text-[var(--text-muted)]">
                Active forwarding: <span className="text-[var(--text)]">{enabledForwarding.join(", ")}</span>
              </div>
            ) : null}
          </div>
        </div>
      </Card>

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <Card padding="lg">
          <h2 className="text-lg font-semibold text-[var(--text)]">Saved PCAPs</h2>
          <p className="mt-1 text-sm text-[var(--text)]">Download or replay captures from storage.</p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input
              value={pcapQuery}
              onChange={(e) => setPcapQuery(e.target.value)}
                placeholder="Search by name, iface, tag"
                className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none md:w-2/3"
              />
              <button
                onClick={() => refresh()}
                className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
              >
                {refreshing ? "Refreshing..." : "Refresh"}
              </button>
            <button
              onClick={() => setPcapQuery("")}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
            >
              Clear search
            </button>
              <button
                onClick={() => uploadInputRef.current?.click()}
                disabled={!canEdit || uploading}
                className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
              >
              {uploading ? "Uploading..." : "Upload PCAP"}
            </button>
            <input
              ref={uploadInputRef}
              type="file"
              accept=".pcap"
              className="hidden"
              onChange={(e) => void handleUpload(e.target.files?.[0] ?? null)}
            />
          </div>
          {lastRefresh ? (
            <div className="mt-2 text-xs text-[var(--text-dim)]">
              Last refreshed: {lastRefresh.toLocaleTimeString()} · Auto-refresh every 8s
            </div>
          ) : null}
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--text-muted)]">
            <span className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[var(--text)]">
              {pcaps.length} total
            </span>
            <span className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[var(--text)]">
              {totalSizeMB.toFixed(1)} MB stored
            </span>
          </div>
          {ifaceStats.length > 0 ? (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--text)]">
              <button
                onClick={() => setIfaceFilter("all")}
                className={`rounded-full px-2 py-0.5 transition-ui ${ifaceFilter === "all" ? "bg-amber-500/[0.15] text-[var(--amber)]" : "bg-amber-500/[0.1] text-[var(--text)]"}`}
              >
                All interfaces
              </button>
              {ifaceStats.map(([iface, stats]) => (
                <button
                  key={iface}
                  onClick={() => setIfaceFilter(iface)}
                  className={`rounded-full px-2 py-0.5 transition-ui ${ifaceFilter === iface ? "bg-amber-500/[0.15] text-[var(--amber)]" : "bg-amber-500/[0.1] text-[var(--text)]"}`}
                >
                  {iface} · {stats.count}
                </button>
              ))}
            </div>
          ) : null}
          <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15]">
            <table className="w-full text-left text-sm text-[var(--text)]">
              <thead className="bg-[var(--surface)] text-xs uppercase tracking-wide text-[var(--text-muted)]">
                <tr>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Iface</th>
                  <th className="px-3 py-2">Size</th>
                  <th className="px-3 py-2">Tags</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visiblePcaps.length === 0 ? (
                  <tr className="border-t border-amber-500/[0.1]">
                    <td colSpan={6} className="px-3 py-3 text-sm text-[var(--text-muted)]">
                      No captures match your filters.
                    </td>
                  </tr>
                ) : (
                  visiblePcaps.map((p) => (
                    <tr key={p.name} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                      <td className="px-3 py-2">
                        <div className="font-mono text-xs text-[var(--text)]">{p.name}</div>
                        <div className="text-[11px] text-[var(--text-muted)]">{new Date(p.createdAt).toLocaleString()}</div>
                      </td>
                      <td className="px-3 py-2">{p.interface || "—"}</td>
                      <td className="px-3 py-2">{(p.sizeBytes / (1024 * 1024)).toFixed(1)} MB</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {(p.tags ?? []).length ? (
                            (p.tags ?? []).map((t) => (
                              <span key={t} className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[10px] text-[var(--text)]">
                                {t}
                              </span>
                            ))
                          ) : (
                            <span className="text-xs text-[var(--text-dim)]">—</span>
                          )}
                        </div>
                        <div className="mt-1 flex items-center gap-1">
                          <input
                            value={pcapTag}
                            onChange={(e) => setPcapTag(e.target.value)}
                            placeholder="add tag"
                            className="w-24 rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                          />
                          <button
                            onClick={() => addTag(p.name)}
                            disabled={!canEdit}
                            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
                          >
                            Add
                          </button>
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <span className="rounded-full bg-amber-500/[0.1] px-2 py-0.5 text-[10px] text-[var(--text)]">{p.status}</span>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <a
                          href={downloadPcapURL(p.name)}
                          className="mr-2 inline-flex rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                        >
                          Download
                        </a>
                        <button
                          onClick={() => void replayPcap({ name: p.name, interface: p.interface })}
                          disabled={!canEdit}
                          className="mr-2 rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
                        >
                          Replay
                        </button>
                        <button
                          onClick={() => {
                            if (!canEdit) return;
                            confirm.open({
                              title: "Delete PCAP",
                              message: `Delete capture "${p.name}"? This cannot be undone.`,
                              confirmLabel: "Delete",
                              variant: "danger",
                              onConfirm: async () => {
                                const ok = await deletePcap(p.name);
                                if (ok) {
                                  setPcaps(await listPcaps());
                                } else {
                                  setNotice("Failed to delete PCAP.");
                                }
                              },
                            });
                          }}
                          disabled={!canEdit}
                          className="rounded-md text-red-400 transition-ui hover:bg-red-500/10 px-2 py-1 text-xs disabled:opacity-50"
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>

        <Card padding="lg">
          <h2 className="text-lg font-semibold text-[var(--text)]">Replay</h2>
          <p className="mt-1 text-sm text-[var(--text)]">Replay a saved PCAP back onto an interface.</p>
          <div className="mt-4 grid gap-3">
            <select
              disabled={!canEdit}
              value={replayName}
              onChange={(e) => {
                const next = e.target.value;
                setReplayName(next);
                const match = pcaps.find((p) => p.name === next);
                if (match?.interface) {
                  setReplayIface(match.interface);
                }
              }}
              className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-50"
            >
              <option value="">Select a PCAP</option>
              {pcaps.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
            <select
              disabled={!canEdit}
              value={replayIface}
              onChange={(e) => setReplayIface(e.target.value)}
              className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-50"
            >
              <option value="">Replay interface</option>
              {ifaceOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <input
              disabled={!canEdit}
              value={replayRate}
              onChange={(e) => setReplayRate(e.target.value)}
              placeholder="Replay rate (pps)"
              className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none disabled:opacity-50"
            />
            <button
              disabled={!canEdit || !replayName || !replayIface}
              onClick={async () => {
                const rate = replayRate.trim() ? Number(replayRate) : undefined;
                const ok = await replayPcap({
                  name: replayName,
                  interface: replayIface,
                  ratePps: Number.isFinite(rate) ? rate : undefined,
                });
                if (!ok) {
                  setNotice("Failed to start replay.");
                }
              }}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08] disabled:opacity-50"
            >
              Start replay
            </button>
          </div>
        </Card>
      </div>
    </Shell>
  );
}

function normalizeConfig(cfg: PcapConfig): PcapConfig {
  return {
    enabled: cfg.enabled ?? false,
    interfaces: cfg.interfaces ?? [],
    snaplen: cfg.snaplen ?? 262144,
    maxSizeMB: cfg.maxSizeMB ?? 64,
    maxFiles: cfg.maxFiles ?? 8,
    mode: cfg.mode ?? "rolling",
    promisc: cfg.promisc ?? true,
    bufferMB: cfg.bufferMB ?? 4,
    rotateSeconds: cfg.rotateSeconds ?? 300,
    filePrefix: cfg.filePrefix ?? "capture",
    filter: {
      src: cfg.filter?.src ?? "",
      dst: cfg.filter?.dst ?? "",
      proto: cfg.filter?.proto ?? "any",
    },
    forwardTargets: cfg.forwardTargets ?? [],
  };
}
