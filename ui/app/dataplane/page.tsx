"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import {
  api,
  isAdmin,
  deletePcap,
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
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { SavedPcapsCard, ReplayCard } from "./pcap-library";
import {
  CaptureSetupCard,
  CaptureStatusCard,
} from "./pcap-settings";
import { normalizeConfig } from "./pcap-utils";

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
  const uploadInputRef = useRef<HTMLInputElement>(null);
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
    const result = await tagPcap({ name: pcapName, tags });
    if (result.ok) {
      setPcapTag("");
      const list = await listPcaps();
      setPcaps(list);
      setNotice(result.warning ? `PCAP tags updated with warning: ${result.warning}` : "PCAP tags updated.");
    } else {
      setNotice(result.error || "Failed to update PCAP tags.");
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
    if (!saved.ok) {
      setNotice(saved.error || "Failed to save capture settings.");
      setState("idle");
      return;
    }
    setSavedConfigJson(JSON.stringify(normalizeConfig(saved.data)));
    const st = await startPcap(saved.data);
    if (!st.ok) {
      setNotice(st.error || "Failed to start capture.");
    } else {
      setStatus(st.data);
      setSettings((prev) => ({ ...prev, enabled: true }));
      setNotice(
        [saved.warning, st.warning].filter(Boolean).length > 0
          ? `Capture started with warning: ${[saved.warning, st.warning].filter(Boolean).join(" | ")}`
          : "Capture started.",
      );
    }
    setState("idle");
    await refresh();
  }

  async function stopCapture() {
    if (!canEdit) return;
    setState("stopping");
    const st = await stopPcap();
    if (!st.ok) {
      setNotice(st.error || "Failed to stop capture.");
    } else {
      setStatus(st.data);
      setSettings((prev) => ({ ...prev, enabled: false }));
      setNotice(st.warning ? `Capture stopped with warning: ${st.warning}` : "Capture stopped.");
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
    if (!saved.ok) {
      setNotice(saved.error || "Failed to save capture settings.");
      return;
    }
    setSettings(normalizeConfig(saved.data));
    setSavedConfigJson(JSON.stringify(normalizeConfig(saved.data)));
    setNotice(saved.warning ? `Capture settings saved with warning: ${saved.warning}` : "Capture settings saved.");
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
    if (!item.ok) {
      setNotice(item.error || "Failed to upload PCAP.");
    } else {
      setNotice(item.warning ? `PCAP uploaded with warning: ${item.warning}` : "PCAP uploaded.");
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
      <CaptureStatusCard
        isRunning={isRunning}
        captureSummary={captureSummary}
        runningSince={runningSince}
        status={status}
        settings={settings}
      />
      <CaptureSetupCard
        canEdit={canEdit}
        settings={settings}
        setSettings={setSettings}
        configIssues={configIssues}
        ifaceOptions={ifaceOptions}
        toggleIface={toggleIface}
        setAllInterfaces={setAllInterfaces}
        bpfPreview={bpfPreview}
        updateForwardTarget={updateForwardTarget}
        enabledForwarding={enabledForwarding}
      />

      <div className="mt-6 grid gap-4 md:grid-cols-2">
        <SavedPcapsCard
          canEdit={canEdit}
          pcapQuery={pcapQuery}
          setPcapQuery={setPcapQuery}
          onRefresh={refresh}
          refreshing={refreshing}
          uploading={uploading}
          uploadInputRef={uploadInputRef}
          onUpload={handleUpload}
          lastRefresh={lastRefresh}
          pcaps={pcaps}
          totalSizeMB={totalSizeMB}
          ifaceStats={ifaceStats}
          ifaceFilter={ifaceFilter}
          setIfaceFilter={setIfaceFilter}
          visiblePcaps={visiblePcaps}
          pcapTag={pcapTag}
          setPcapTag={setPcapTag}
          onAddTag={addTag}
          onReplayInline={(p) => {
            void (async () => {
              const result = await replayPcap({ name: p.name, interface: p.interface });
              setNotice(
                result.ok
                  ? result.warning
                    ? `Replay started with warning: ${result.warning}`
                    : "Replay started."
                  : result.error || "Failed to start replay.",
              );
            })();
          }}
          onDelete={(p) => {
            if (!canEdit) return;
            confirm.open({
              title: "Delete PCAP",
              message: `Delete capture "${p.name}"? This cannot be undone.`,
              confirmLabel: "Delete",
              variant: "danger",
              onConfirm: async () => {
                const result = await deletePcap(p.name);
                if (result.ok) {
                  setPcaps(await listPcaps());
                  setNotice(result.warning ? `PCAP deleted with warning: ${result.warning}` : "PCAP deleted.");
                } else {
                  setNotice(result.error || "Failed to delete PCAP.");
                }
              },
            });
          }}
        />

        <ReplayCard
          canEdit={canEdit}
          replayName={replayName}
          setReplayName={(next) => {
            const value = typeof next === "function" ? next(replayName) : next;
            setReplayName(value);
            const match = pcaps.find((p) => p.name === value);
            if (match?.interface) {
              setReplayIface(match.interface);
            }
          }}
          replayIface={replayIface}
          setReplayIface={setReplayIface}
          replayRate={replayRate}
          setReplayRate={setReplayRate}
          pcaps={pcaps}
          ifaceOptions={ifaceOptions}
          onReplaySubmit={async () => {
            const rate = replayRate.trim() ? Number(replayRate) : undefined;
            const result = await replayPcap({
              name: replayName,
              interface: replayIface,
              ratePps: Number.isFinite(rate) ? rate : undefined,
            });
            setNotice(
              result.ok
                ? result.warning
                  ? `Replay started with warning: ${result.warning}`
                  : "Replay started."
                : result.error || "Failed to start replay.",
            );
          }}
        />
      </div>
    </Shell>
  );
}
