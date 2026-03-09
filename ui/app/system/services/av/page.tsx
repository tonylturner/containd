"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api, isAdmin, type AVConfig } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { useToast } from "../../../../components/ToastProvider";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { Card } from "../../../../components/Card";
import { ConfirmDialog, useConfirm } from "../../../../components/ConfirmDialog";

type SaveState = "idle" | "saving" | "saved" | "error";

const emptyICAPServer = { address: "", useTls: false, service: "" };

export default function AVPage() {
  const canEdit = isAdmin();
  const toast = useToast();
  const confirm = useConfirm();
  const [cfg, setCfg] = useState<AVConfig>({
    enabled: false,
    mode: "icap",
    failPolicy: "open",
    failOpenIcs: true,
    icap: { servers: [] },
    clamav: { freshclamEnabled: true },
  });
  const [status, setStatus] = useState<any>(null);
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);
  const [defs, setDefs] = useState<string[]>([]);
  const [uploading, setUploading] = useState(false);
  const [defsPath, setDefsPath] = useState<string>("");
  const [notice, setNotice] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setRefreshError(null);
    try {
      const svc = await api.getServicesStatus();
      setStatus((svc as any)?.av ?? null);
      const s = await api.getAV();
      if (s) setCfg(s);
      const defsResp = await api.listAVDefs();
      setDefs(defsResp?.files ?? []);
      setDefsPath(defsResp?.path ?? "");
      toast("AV status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to refresh AV.";
      setRefreshError(msg);
      toast("Failed to refresh AV", "error");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const icapServers = useMemo(() => cfg.icap?.servers ?? [], [cfg.icap?.servers]);

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const result = await api.setAV(cfg);
    if (result.ok) {
      setSaveState("saved");
      setCfg(result.data);
      toast("AV settings saved", "success");
    } else {
      setSaveState("error");
      const msg = result.error || "Failed to save AV settings.";
      setError(msg);
      toast(msg, "error");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function onRunUpdate() {
    setUpdateMsg(null);
    setUpdating(true);
    const res = await api.runAVUpdate();
    setUpdating(false);
    setUpdateMsg(res ? "Definition update triggered." : "Failed to trigger update.");
    toast(res ? "Definition update triggered" : "Failed to trigger update", res ? "success" : "error");
    refresh();
  }

  function updateICAPServer(idx: number, field: string, value: any) {
    setCfg((c) => {
      const servers = [...(c.icap?.servers ?? [])];
      servers[idx] = { ...servers[idx], [field]: value };
      return { ...c, icap: { ...(c.icap ?? {}), servers } };
    });
  }

  function addICAPServer() {
    setCfg((c) => ({
      ...c,
      icap: { ...(c.icap ?? {}), servers: [ ...(c.icap?.servers ?? []), { ...emptyICAPServer } ] },
    }));
  }

  function deleteICAPServer(idx: number) {
    setCfg((c) => ({
      ...c,
      icap: { ...(c.icap ?? {}), servers: (c.icap?.servers ?? []).filter((_, i) => i !== idx) },
    }));
  }

  return (
    <Shell
      title="Antivirus / ICAP"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => refresh()}
            className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
          >
            Refresh
          </button>
          {canEdit && cfg.mode === "clamav" && (
            <button
              onClick={onRunUpdate}
              disabled={updating}
              className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-sm text-slate-200 transition-ui hover:bg-white/[0.08] disabled:opacity-50"
            >
              {updating ? "Updating\u2026" : "Run definition update"}
            </button>
          )}
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-ui hover:bg-blue-500"
            >
              Save
            </button>
          )}
          <label className="ml-2 flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded border-white/20 bg-black/30"
            />
            Auto
          </label>
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {!canEdit && (
        <div className="mb-4 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {refreshError && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {refreshError}
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-slate-400">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>
      {(updateMsg || notice) && (
        <div className="mb-4 space-y-2">
          {updateMsg && (
            <div className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-2 text-sm text-slate-200">
              {updateMsg}
            </div>
          )}
          {notice && (
            <div className="rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-400">
              {notice}
            </div>
          )}
        </div>
      )}

      <Card className="mb-4">
        <h2 className="text-sm font-semibold text-white">Runtime status</h2>
        {loading || !status ? (
          <div className="mt-3 space-y-2">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-10 w-1/2" />
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-slate-200 md:grid-cols-3">
            <div>Enabled: <span className="text-slate-100">{status?.enabled ? "yes" : "no"}</span></div>
            <div>Mode: <span className="text-slate-100">{status?.mode ?? cfg.mode ?? "icap"}</span></div>
            <div>Fail policy: <span className="text-slate-100">{status?.failPolicy ?? cfg.failPolicy ?? "open"}</span></div>
            <div>
              Rate: <span className="text-slate-100">{typeof status?.rate_per_min === "number" ? status?.rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>
              Errors: <span className="text-amber-300">{typeof status?.errors_rate_per_min === "number" ? status?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>ICS fail-open: <span className="text-slate-100">{status?.failOpenICS ?? cfg.failOpenIcs ? "yes" : "no"}</span></div>
            <div>ICAP servers: <span className="text-slate-100">{status?.icap_servers ?? 0}</span></div>
            <div>Cache: <span className="text-slate-100">{status?.cache_size ?? 0}</span></div>
            <div>Queue depth: <span className="text-slate-100">{status?.queue_depth ?? 0}</span></div>
            <div>ClamAV running: <span className="text-slate-100">{status?.clamav_running ? `yes (pid ${status?.clamav_pid ?? ""})` : "no"}</span></div>
            <div>ClamAV socket: <span className="text-slate-100">{status?.clamav_socket || "n/a"}</span></div>
            <div>ClamAV last start: <span className="text-slate-100">{status?.clamav_last_start || "never"}</span></div>
            <div>Freshclam: <span className="text-slate-100">{status?.freshclam_enabled ? (status?.freshclam_running ? "running" : "enabled") : "disabled"}</span></div>
            <div>Freshclam last: <span className="text-slate-100">{status?.freshclam_last || "never"}</span></div>
            <div>Freshclam interval: <span className="text-slate-100">{status?.freshclam_interval || "6h"}</span></div>
            <div>Block TTL: <span className="text-slate-100">{status?.block_ttl ?? cfg.blockTtlSeconds ?? 600}s</span></div>
            <div>Custom defs path: <span className="text-slate-100">{defsPath || status?.clamav_custom_defs || cfg.clamav?.customDefsPath || "/data/clamav/custom"}</span></div>
            <div className="md:col-span-3">
              <Sparkline
                values={[
                  (status?.clamav_custom_defs ?? 0) + 2,
                  5,
                  (status?.block_ttl ?? 6) / 60,
                  8,
                  (defs?.length ?? 1) + 4,
                  7,
                  9,
                ]}
                color="var(--purple)"
                background="linear-gradient(180deg, rgba(139,92,246,0.08), rgba(37,99,235,0.04))"
                title="AV detections/updates trend (simulated)"
              />
            </div>
            <div className="md:col-span-3 text-xs text-amber-300">{status?.last_error}</div>
            <div className="md:col-span-3 text-xs text-amber-300">{status?.freshclam_error}</div>
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-white">Settings</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, enabled: e.target.checked }))}
              className="h-4 w-4"
            />
            Enable AV/ICAP scanning
          </label>
          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Mode</label>
            <select
              value={cfg.mode ?? "icap"}
              disabled={!canEdit}
              onChange={(e) => {
                const mode = e.target.value as AVConfig["mode"];
                setCfg((c) => {
                  const next = { ...c, mode };
                  // Auto-populate required ClamAV socket path if switching to clamav mode
                  if (mode === "clamav" && !c.clamav?.socketPath) {
                    next.clamav = { ...(c.clamav ?? {}), socketPath: "/var/run/clamav/clamd.sock" };
                  }
                  return next;
                });
              }}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              <option value="icap">ICAP (external)</option>
              <option value="clamav">ClamAV (embedded)</option>
            </select>
          </div>
          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Fail policy</label>
            <select
              value={cfg.failPolicy ?? "open"}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, failPolicy: e.target.value as AVConfig["failPolicy"] }))}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              <option value="open">Fail open</option>
              <option value="closed">Fail closed</option>
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={cfg.failOpenIcs ?? true}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, failOpenIcs: e.target.checked }))}
              className="h-4 w-4"
            />
            Always fail open for ICS traffic
          </label>
          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Max size (bytes)</label>
            <input
              type="number"
              value={cfg.maxSizeBytes ?? 0}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, maxSizeBytes: Number(e.target.value) }))}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Block TTL (seconds)</label>
            <input
              type="number"
              value={cfg.blockTtlSeconds ?? 600}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, blockTtlSeconds: Number(e.target.value) }))}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">Timeout (seconds)</label>
            <input
              type="number"
              value={cfg.timeoutSec ?? 0}
              disabled={!canEdit}
              onChange={(e) => setCfg((c) => ({ ...c, timeoutSec: Number(e.target.value) }))}
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
        </div>
        {notice && (
          <div className="mt-2 rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-xs text-emerald-400">
            {notice}
          </div>
        )}

        <div className="mt-6">
          <h3 className="text-sm font-semibold text-white">ICAP servers</h3>
          <p className="text-xs text-slate-400">Use when mode is ICAP; leave empty to disable.</p>
          <div className="mt-3 space-y-2">
            {icapServers.map((srv, idx) => (
              <div key={idx} className="grid gap-2 rounded-lg border border-white/[0.08] bg-black/30 p-3 md:grid-cols-4">
                <input
                  value={srv.address}
                  onChange={(e) => updateICAPServer(idx, "address", e.target.value)}
                  disabled={!canEdit}
                  placeholder="host:port"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  value={srv.service ?? ""}
                  onChange={(e) => updateICAPServer(idx, "service", e.target.value)}
                  disabled={!canEdit}
                  placeholder="service (optional)"
                  className="rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <label className="flex items-center gap-2 text-sm text-slate-200">
                  <input
                    type="checkbox"
                    checked={srv.useTls ?? false}
                    disabled={!canEdit}
                    onChange={(e) => updateICAPServer(idx, "useTls", e.target.checked)}
                    className="h-4 w-4"
                  />
                  TLS
                </label>
                {canEdit && (
                  <button
                    onClick={() => deleteICAPServer(idx)}
                    className="rounded-lg border border-white/[0.08] px-3 py-2 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                  >
                    Delete
                  </button>
                )}
              </div>
            ))}
            {canEdit && (
              <button
                onClick={addICAPServer}
                className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-2 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
              >
                Add server
              </button>
            )}
          </div>
        </div>

        <div className="mt-6">
          <h3 className="text-sm font-semibold text-white">ClamAV</h3>
          <p className="text-xs text-slate-400">Used when mode is ClamAV (embedded).</p>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Socket path</label>
              <input
                value={cfg.clamav?.socketPath ?? ""}
                disabled={!canEdit}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), socketPath: e.target.value } }))
                }
                placeholder="/var/run/clamav/clamd.sock"
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Custom defs path</label>
              <input
                value={cfg.clamav?.customDefsPath ?? ""}
                disabled={!canEdit}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), customDefsPath: e.target.value } }))
                }
                placeholder="/data/clamav/custom.d"
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-slate-400">Update schedule</label>
              <input
                value={cfg.clamav?.updateSchedule ?? ""}
                disabled={!canEdit}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), updateSchedule: e.target.value } }))
                }
                placeholder="e.g. 4h or cron expr"
                className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-200">
              <input
                type="checkbox"
                checked={cfg.clamav?.freshclamEnabled ?? true}
                disabled={!canEdit}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), freshclamEnabled: e.target.checked } }))
                }
                className="h-4 w-4"
              />
              Enable definition auto-update
            </label>
          </div>
        </div>

        <div className="mt-6">
          <h3 className="text-sm font-semibold text-white">Custom definitions</h3>
          <p className="text-xs text-slate-400">Upload .ndb/.ldb/.yara files into the custom defs path.</p>
          <div className="mt-3 flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <label className="text-xs uppercase tracking-wide text-slate-400">
                Upload file
                <input
                  type="file"
                  className="mt-1 text-sm text-slate-200"
                  disabled={!canEdit || uploading}
                  onChange={async (e) => {
                    if (!e.target.files?.length) return;
                    setUploading(true);
                    const f = e.target.files[0];
                    const ok = await api.uploadAVDef(f);
                    setUpdateMsg(ok ? `Uploaded ${f.name}` : `Upload failed for ${f.name}`);
                    toast(ok ? `Uploaded ${f.name}` : `Upload failed for ${f.name}`, ok ? "success" : "error");
                    setUploading(false);
                    refresh();
                  }}
                />
              </label>
            </div>
            <div className="rounded-lg border border-white/[0.08] bg-black/30 p-3 text-xs text-slate-200">
              <div className="mb-2 font-semibold text-white">Existing defs</div>
              {defsPath && <div className="mb-2 text-[10px] text-slate-400">Path: {defsPath}</div>}
              {defs.length === 0 && <div className="text-slate-400">None uploaded.</div>}
              {defs.length > 0 && (
                <ul className="space-y-1">
                  {defs.map((d) => (
                    <li key={d} className="flex items-center justify-between rounded border border-white/[0.08] bg-black/20 px-2 py-1">
                      <span>{d}</span>
                      {canEdit && (
                        <button
                          className="text-xs text-red-400 transition-ui hover:bg-red-500/10"
                          onClick={() => {
                            confirm.open({
                              title: "Delete definition",
                              message: `Delete ${d}?`,
                              variant: "danger",
                              confirmLabel: "Delete",
                              onConfirm: async () => {
                                const ok = await api.deleteAVDef(d);
                                setUpdateMsg(ok ? `Deleted ${d}` : `Failed to delete ${d}`);
                                toast(ok ? `Deleted ${d}` : `Failed to delete ${d}`, ok ? "success" : "error");
                                refresh();
                              },
                            });
                          }}
                        >
                          Delete
                        </button>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      </Card>

      <p className="mt-3 text-xs text-slate-400">
        State:{" "}
        {saveState === "saving"
          ? "saving\u2026"
          : saveState === "saved"
            ? "saved"
            : saveState === "error"
              ? "error"
              : "idle"}
      </p>
    </Shell>
  );
}
