"use client";

import { Card } from "../../components/Card";
import { InfoTip } from "../../components/InfoTip";
import type {
  InterfaceState,
  PcapConfig,
  PcapStatus,
} from "../../lib/api";

type CaptureMode = "once" | "rolling";
type PcapForwardRow = {
  interface?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  proto?: "tcp" | "udp";
};

export function CaptureStatusCard({
  isRunning,
  captureSummary,
  runningSince,
  status,
  settings,
}: {
  isRunning: boolean;
  captureSummary: string;
  runningSince: string;
  status: PcapStatus | null;
  settings: PcapConfig;
}) {
  return (
    <Card className="mb-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--text)]">
            Capture Status
          </div>
          <div className="mt-1 text-sm text-[var(--text)]">
            {isRunning ? "Running" : "Stopped"}
          </div>
        </div>
        <span
          className={`rounded-full px-2 py-0.5 text-xs ${isRunning ? "bg-emerald-500/20 text-emerald-400" : "bg-amber-500/[0.1] text-[var(--text)]"}`}
        >
          {isRunning ? "active" : "idle"}
        </span>
      </div>
      <div className="mt-2 text-xs text-[var(--text-muted)]">
        {captureSummary}
      </div>
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
  );
}

export function CaptureSetupCard({
  canEdit,
  settings,
  setSettings,
  configIssues,
  ifaceOptions,
  toggleIface,
  setAllInterfaces,
  bpfPreview,
  updateForwardTarget,
  enabledForwarding,
}: {
  canEdit: boolean;
  settings: PcapConfig;
  setSettings: React.Dispatch<React.SetStateAction<PcapConfig>>;
  configIssues: string[];
  ifaceOptions: { value: string; label: string }[];
  toggleIface: (name: string) => void;
  setAllInterfaces: (on: boolean) => void;
  bpfPreview: string;
  updateForwardTarget: (iface: string, patch: Partial<PcapForwardRow>) => void;
  enabledForwarding: string[];
}) {
  return (
    <Card padding="lg">
      <h2 className="text-lg font-semibold text-[var(--text)]">
        Capture setup
      </h2>
      <p className="mt-1 text-sm text-[var(--text)]">
        Start/stop packet captures on selected interfaces and store PCAPs for
        replay.
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
              <label
                key={opt.value}
                className="flex items-center gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui"
              >
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
              onChange={(e) =>
                setSettings((prev) => ({
                  ...prev,
                  mode: e.target.value as CaptureMode,
                }))
              }
              className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
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
              onChange={(e) =>
                setSettings((prev) => ({
                  ...prev,
                  snaplen: Number(e.target.value) || 0,
                }))
              }
              className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
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
              onChange={(e) =>
                setSettings((prev) => ({
                  ...prev,
                  maxSizeMB: Number(e.target.value) || 0,
                }))
              }
              className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
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
              onChange={(e) =>
                setSettings((prev) => ({
                  ...prev,
                  maxFiles: Number(e.target.value) || 0,
                }))
              }
              className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
            />
          </div>
          <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-3 md:col-span-2">
            <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Filters (tcpdump style)
            </div>
            <div className="mt-2 grid gap-2 md:grid-cols-3">
              <input
                value={settings.filter?.src ?? ""}
                disabled={!canEdit}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    filter: { ...(prev.filter ?? {}), src: e.target.value },
                  }))
                }
                placeholder="src host 10.0.0.10"
                className="input-industrial transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
              />
              <input
                value={settings.filter?.dst ?? ""}
                disabled={!canEdit}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    filter: { ...(prev.filter ?? {}), dst: e.target.value },
                  }))
                }
                placeholder="dst host 10.0.0.20"
                className="input-industrial transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
              />
              <select
                value={settings.filter?.proto ?? "any"}
                disabled={!canEdit}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    filter: {
                      ...(prev.filter ?? {}),
                      proto: e.target.value as "any" | "tcp" | "udp" | "icmp",
                    },
                  }))
                }
                className="input-industrial transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
              >
                <option value="any">any proto</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
                <option value="icmp">icmp</option>
              </select>
            </div>
            <div className="mt-2 text-xs text-[var(--text-muted)]">
              Filter preview:{" "}
              <span className="font-mono text-[var(--text)]">{bpfPreview}</span>
            </div>
          </div>
        </div>

        <details className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
          <summary className="cursor-pointer text-sm text-[var(--text)]">
            Advanced capture options
          </summary>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                File prefix
                <InfoTip label="Prefix for saved PCAP files." />
              </label>
              <input
                value={settings.filePrefix}
                disabled={!canEdit}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    filePrefix: e.target.value,
                  }))
                }
                className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
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
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    rotateSeconds: Number(e.target.value) || 0,
                  }))
                }
                className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
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
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    bufferMB: Number(e.target.value) || 0,
                  }))
                }
                className="input-industrial mt-1 w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-[var(--text)]">
              <input
                type="checkbox"
                checked={settings.promisc}
                disabled={!canEdit}
                onChange={(e) =>
                  setSettings((prev) => ({
                    ...prev,
                    promisc: e.target.checked,
                  }))
                }
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
              <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
                PCAP Forwarding (Remote Sensor)
              </div>
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
              if (!target.interface) {
                return null;
              }
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
                      onChange={(e) =>
                        updateForwardTarget(iface, {
                          enabled: e.target.checked,
                        })
                      }
                      className="h-4 w-4 rounded border-white/20 bg-[var(--surface)]"
                    />
                    {iface}
                  </label>
                  <input
                    value={target.host}
                    disabled={!canEdit || !target.enabled}
                    onChange={(e) =>
                      updateForwardTarget(iface, { host: e.target.value })
                    }
                    placeholder="sensor.example.local"
                    className="input-industrial w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring disabled:opacity-60"
                  />
                  <input
                    type="number"
                    value={target.port}
                    disabled={!canEdit || !target.enabled}
                    onChange={(e) =>
                      updateForwardTarget(iface, {
                        port: Number(e.target.value) || 0,
                      })
                    }
                    className="input-industrial w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring disabled:opacity-60"
                  />
                  <select
                    value={target.proto}
                    disabled={!canEdit || !target.enabled}
                    onChange={(e) =>
                      updateForwardTarget(iface, {
                        proto: e.target.value as "tcp" | "udp",
                      })
                    }
                    className="input-industrial w-full transition-ui outline-none focus:border-amber-500/40 focus-visible:shadow-focus-ring disabled:opacity-60"
                  />
                </div>
              );
            })}
          </div>
          <div className="mt-2 text-xs text-[var(--text-muted)]">
            Streams PCAP data to remote collectors; configure one target per
            interface.
          </div>
          {enabledForwarding.length > 0 ? (
            <div className="mt-2 text-xs text-[var(--text-muted)]">
              Active forwarding:{" "}
              <span className="text-[var(--text)]">
                {enabledForwarding.join(", ")}
              </span>
            </div>
          ) : null}
        </div>
      </div>
    </Card>
  );
}
