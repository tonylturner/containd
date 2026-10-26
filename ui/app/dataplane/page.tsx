"use client";

import { useConfigRefresh } from "../../lib/use-config-refresh";

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
  type Zone,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { SavedPcapsCard, ReplayCard } from "./pcap-library";
import {
  CaptureSetupCard,
  CaptureStatusCard,
} from "./pcap-settings";
import { normalizeConfig } from "./pcap-utils";

type SaveState = "idle" | "starting" | "stopping";

type PcapForwardRow = PcapForwardTarget & { interface: string };

export default function PcapPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const [ifaces, setIfaces] = useState<Interface[]>([]);
  const [zones, setZones] = useState<Zone[]>([]);
  const [ifaceStateStatus, setIfaceStateStatus] = useState<"loading" | "ready" | "unavailable">("loading");
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
    zones: [],
    snaplen: 262144,
    maxSizeMB: 64,
    maxFiles: 8,
    mode: "rolling",
    promisc: true,
    bufferMB: 4,
    rotateSeconds: 300,
    filePrefix: "capture",
    filter: { src: "", dst: "", proto: "any", port: "" },
    forwardTargets: [],
  });

  const settingsSnapshot = useMemo(
    () => JSON.stringify(normalizeConfig(settings)),
    [settings],
  );
  const isDirty = savedConfigJson ? settingsSnapshot !== savedConfigJson : false;
  useConfigRefresh(() => {
    void refresh();
    void api.listInterfaces().then((list) => setIfaces(list ?? []));
    void api.listZones().then((list) => setZones(list ?? []));
  });

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
    api.listZones().then((list) => setZones(list ?? []));
    void refreshInterfaceState();
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

  async function refreshInterfaceState() {
    const list = await api.listInterfaceState();
    setIfaceStates(list ?? []);
    setIfaceStateStatus(list === null ? "unavailable" : "ready");
  }

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

  const captureIfaceOptions = useMemo(() => {
    const options = new Map<string, string>();
    const osSet = new Set((ifaceStates ?? []).map((s) => s.name));
    const mappedDevices = new Set<string>();
    for (const iface of ifaces ?? []) {
      const device = iface.device?.trim();
      const kernelDevice = device || iface.name;
      if (!device && !osSet.has(kernelDevice)) continue;
      if (kernelDevice) mappedDevices.add(kernelDevice);
      const label = device && device !== iface.name ? `${iface.name} (${device})` : iface.name;
      options.set(iface.name, iface.alias ? `${iface.alias} (${label})` : label);
    }
    for (const state of ifaceStates) {
      if (!mappedDevices.has(state.name)) {
        options.set(state.name, `${state.name} (kernel device)`);
      }
    }
    for (const selected of settings.interfaces ?? []) {
      if (!options.has(selected)) options.set(selected, `${selected} (saved selection)`);
    }
    return Array.from(options.entries()).map(([value, label]) => ({ value, label }));
  }, [ifaces, ifaceStates, settings.interfaces]);

  const zoneOptions = useMemo(() => {
    const configured: Zone[] = zones.length
      ? zones
      : Array.from(new Set(ifaces.map((iface) => iface.zone).filter(Boolean))).map(
          (name): Zone => ({ name: name as string }),
        );
    return configured.map((zone) => ({
      value: zone.name,
      label: zone.alias ? `${zone.alias} (${zone.name})` : zone.name,
    }));
  }, [ifaces, zones]);

  useEffect(() => {
    if (ifaceStateStatus !== "ready") return;
    setSettings((prev) => {
      // Discovery adds choices; it must never delete saved forwarding targets.
      const existing = new Set((prev.forwardTargets ?? []).map((target) => target.interface));
      const added = ifaceOptions.filter((iface) => !existing.has(iface.value)).map((iface) => ({
        interface: iface.value,
        enabled: false,
        host: "",
        port: 9000,
        proto: "udp" as const,
      }));
      return { ...prev, forwardTargets: [...(prev.forwardTargets ?? []), ...added] };
    });
  }, [ifaceOptions, ifaceStateStatus]);

  const bpfPreview = useMemo(() => {
    const clauses: string[] = [];
    const filter = settings.filter ?? {};
    if (filter.proto && filter.proto !== "any") clauses.push(filter.proto);
    if (filter.src?.trim()) clauses.push(`src host ${filter.src.trim()}`);
    if (filter.dst?.trim()) clauses.push(`dst host ${filter.dst.trim()}`);
    if (filter.port?.trim()) clauses.push(`port ${filter.port.trim()}`);
    return clauses.length ? clauses.join(" and ") : "not set";
  }, [settings.filter]);
  const configIssues = useMemo(() => {
    const issues: string[] = [];
    if ((settings.interfaces ?? []).length === 0 && (settings.zones ?? []).length === 0) {
      issues.push("Select at least one interface or zone to capture.");
    }
    if (ifaceStateStatus === "ready" && captureIfaceOptions.length === 0 && zoneOptions.length === 0) {
      issues.push("No firewall interfaces are bound to OS devices. Set device bindings on the Interfaces page.");
    }
    for (const selectedZone of settings.zones ?? []) {
      if (!zoneOptions.some((zone) => zone.value === selectedZone)) {
        issues.push(`Zone "${selectedZone}" is not configured.`);
      } else if (!ifaces.some((iface) => iface.zone === selectedZone)) {
        issues.push(`Zone "${selectedZone}" has no configured interfaces.`);
      }
    }
    if (ifaceStateStatus === "ready") {
      const available = new Set(ifaceStates.map((i) => i.name));
      const deviceByLogical = new Map(
        ifaces.map((iface) => [iface.name, iface.device?.trim() || iface.name]),
      );
      const selectedDevices = new Set(
        (settings.interfaces ?? []).map((name) => deviceByLogical.get(name) ?? name),
      );
      for (const iface of ifaces) {
        if (iface.zone && (settings.zones ?? []).includes(iface.zone)) {
          selectedDevices.add(iface.device?.trim() || iface.name);
        }
      }
      const missing = Array.from(selectedDevices).filter((name) => !available.has(name));
      if (missing.length > 0) {
        issues.push(`Kernel devices not found: ${missing.join(", ")}. Bind the interfaces or choose an available device.`);
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
    const port = (settings.filter?.port ?? "").trim();
    if (
      port &&
      (!/^\d+(?:-\d+)?$/.test(port) ||
        port.split("-").some((part) => Number(part) < 1 || Number(part) > 65535) ||
        (port.includes("-") &&
          Number(port.split("-")[0]) > Number(port.split("-")[1])))
    ) {
      issues.push("Port must be 1–65535 or an inclusive range such as 1000-2000.");
    }
    if (port && settings.filter?.proto === "icmp") {
      issues.push("Port filters apply only to TCP and UDP.");
    }
    return issues;
  }, [settings, ifaces, ifaceStates, ifaceStateStatus, captureIfaceOptions.length, zoneOptions]);
  const isRunning = status?.running ?? false;
  const canStart = canEdit && status !== null && configIssues.length === 0 && state === "idle" && !isRunning;
  const captureSummary = useMemo(() => {
    const selections = [
      ...(settings.interfaces ?? []),
      ...(settings.zones ?? []).map((zone) => `zone ${zone}`),
    ];
    const ifaceLabel = selections.length
      ? selections.join(", ")
      : "no interfaces or zones";
    const rotation =
      settings.mode === "rolling"
        ? `${settings.maxFiles ?? 0} files @ ${settings.maxSizeMB ?? 0}MB`
        : `${settings.maxSizeMB ?? 0}MB max`;
    return `${ifaceLabel} · ${rotation} · snaplen ${settings.snaplen ?? 0}`;
  }, [settings.interfaces, settings.zones, settings.mode, settings.maxFiles, settings.maxSizeMB, settings.snaplen]);
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

  function toggleZone(name: string) {
    setSettings((prev) => {
      const set = new Set(prev.zones ?? []);
      if (set.has(name)) set.delete(name);
      else set.add(name);
      return { ...prev, zones: Array.from(set) };
    });
  }

  function setAllInterfaces(on: boolean) {
    setSettings((prev) => ({
      ...prev,
      interfaces: on ? captureIfaceOptions.map((opt) => opt.value) : [],
      zones: [],
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
    const st = await startPcap(settings);
    if (!st.ok) {
      setNotice(st.error || "Failed to start capture.");
    } else {
      setStatus(st.data);
      setNotice(
        st.warning
          ? `Capture started with warning: ${st.warning}`
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
    setNotice(saved.warning ? `PCAP defaults staged — commit to apply. Warning: ${saved.warning}` : "PCAP defaults staged — commit to apply.");
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
                className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
              >
                Save PCAP defaults
              </button>
              <button
                onClick={startCapture}
                disabled={!canStart}
                className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui disabled:opacity-50"
              >
                {state === "starting" ? "Starting..." : "Start capture now"}
              </button>
              <button
                onClick={stopCapture}
                disabled={state !== "idle" || !isRunning}
                className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
              >
                {state === "stopping" ? "Stopping..." : "Stop"}
              </button>
            </>
          ) : (
            <span className="text-xs text-(--text-muted)">View-only</span>
          )}
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {ifaceStateStatus === "unavailable" && (
        <div role="status" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <p>Interface runtime state unavailable — the engine could not be reached. Device discovery is unknown; saved capture settings are unchanged.</p>
          <button onClick={refreshInterfaceState} className="mt-2 rounded-xs border border-red-500/30 px-3 py-1">Retry</button>
        </div>
      )}
      {ifaceStateStatus === "ready" && ifaceStates.length === 0 && <p role="status" className="mb-4 text-sm text-(--text)">No OS interfaces reported.</p>}

      {notice && (
        <div className="mb-4 rounded-xs border px-3 py-2 text-sm">
          {notice}
        </div>
      )}
      <CaptureStatusCard
        isRunning={isRunning}
        captureSummary={captureSummary}
        runningSince={runningSince}
        status={status}
      />
      <CaptureSetupCard
        canEdit={canEdit}
        settings={settings}
        setSettings={setSettings}
        configIssues={configIssues}
        captureIfaceOptions={captureIfaceOptions}
        zoneOptions={zoneOptions}
        toggleIface={toggleIface}
        toggleZone={toggleZone}
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
