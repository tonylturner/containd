"use client";

import { useAsyncRefresh } from "../../../../hooks/useAsyncRefresh";

import { revisionError, useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../../../lib/use-config-editor";

import { useConfigRefresh } from "../../../../lib/use-config-refresh";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type Asset, type AVConfig, type ServicesStatus, type Zone } from "../../../../lib/api";
import { ServiceFaultBanner } from "../../../../components/ServiceFaultBanner";
import { Shell } from "../../../../components/Shell";
import { useToast } from "../../../../components/ToastProvider";
import { SaveStateLine } from "../../../../components/SaveStateLine";
import { useSaveAction } from "../../../../hooks/useSaveAction";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { ServiceStatusStrip } from "../service-presentation";
import { Disclosure } from "../../../../components/Disclosure";
import { Card } from "../../../../components/Card";
import { ConfirmDialog, useConfirm } from "../../../../components/ConfirmDialog";
import { CustomDefinitions } from "./custom-defs";
import { GateStatus, GateSummary } from "./gate-status";
import { normalizeScan } from "./scan-model";
import { ScanSelectionEditor } from "./scan-selection";

const emptyICAPServer = { address: "", useTls: false, service: "" };
const effectiveMode = <T extends string,>(mode: T | undefined): T | "clamav" => mode ?? "clamav";

export default function AVPage() {
  const canEdit = isAdmin();
  const confirm = useConfirm();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const toast = useToast();
  const { conflictProps, editor, cfg, setCfg, readConfig: adoptConfig, write } = useConfigEditor<AVConfig>({
    enabled: false,
    mode: "clamav",
    failPolicy: "open",
    icap: { servers: [] },
  }, false);
  const [zones, setZones] = useState<Zone[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [servicesStatus, setServicesStatus] = useState<ServicesStatus | null>(null);
  const status = servicesStatus?.av ?? null;
  const save = useSaveAction();
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);
  const [defs, setDefs] = useState<string[]>([]);
  const [defsPath, setDefsPath] = useState<string>("");
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    try {
      const svc = await api.getServicesStatus();
      setRefreshError(null);
      setServicesStatus(svc);
      const sSnapshot = await api.getAV();
      const s = (sSnapshot?.data ?? null);
      if (!checkLoaded(s)) return;
      adoptConfig({ data: { ...s, mode: effectiveMode(s.mode) }, revision: sSnapshot?.revision ?? "" }, keepEdits);
      const [zoneListSnapshot, assetListSnapshot] = await Promise.all([api.listZones(), api.listAssets()]);
      const zoneList = (zoneListSnapshot?.data ?? null);
      const assetList = (assetListSnapshot?.data ?? null);
      setZones(zoneList ?? []);
      setAssets(assetList ?? []);
      const defsResp = await api.listAVDefs();
      setDefs(defsResp?.files ?? []);
      setDefsPath(defsResp?.path ?? "");
      toast("AV status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      checkLoaded(null);
      const msg = e instanceof Error ? e.message : "Failed to refresh AV.";
      setRefreshError(msg);
      toast("Failed to refresh AV", "error");
    }
  }, [checkLoaded, toast, adoptConfig]));

  useConfigRefresh(refresh);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const icapServers = useMemo(() => cfg.icap?.servers ?? [], [cfg.icap?.servers]);
  const missingDatabase = cfg.mode === "clamav" && status?.available &&
    /database|signature/i.test([status.ready_error, status.last_error, status.fault?.message].filter(Boolean).join(" "));
  const localScannerCustomized = Boolean(
    (cfg.clamav?.socketPath && cfg.clamav.socketPath !== "/run/clamav/clamd.sock") ||
    (cfg.clamav?.customDefsPath && cfg.clamav.customDefsPath !== "/data/clamav/custom") ||
    cfg.clamav?.updateSchedule ||
    cfg.clamav?.freshclamEnabled === true
  );

  async function onSave() {
    if (!canEdit || !canSave || loading) return;
    setError(null);
    if (cfg.cacheTtl !== undefined && (!Number.isInteger(cfg.cacheTtl) || cfg.cacheTtl < 0)) {
      setError("Cache TTL must be a non-negative duration representable in whole nanoseconds.");
      return;
    }
    const payload: AVConfig = {
      ...cfg,
      scan: normalizeScan(cfg.scan),
    };
    const result = await save.run("save", () => write(base => api.setAV(base, payload), { replace: data => data }), {
      success: "AV settings staged — commit to apply.",
      failure: "Failed to save AV settings.",
    });
    if (!result) return;
    if (!result.ok) setError(revisionError(result));
  }

  async function onRunUpdate() {
    setUpdateMsg(null);
    setUpdating(true);
    const result = await api.runAVUpdate();
    setUpdating(false);
    if (result.ok) {
      setUpdateMsg(result.warning ? `Definition update triggered with warning: ${result.warning}` : "Definition update triggered.");
      toast(result.warning ? `Definition update triggered with warning: ${result.warning}` : "Definition update triggered", "success");
    } else {
      const msg = result.error || "Failed to trigger update.";
      setUpdateMsg(msg);
      toast(msg, "error");
    }
    refresh();
  }

  function confirmUpdate() {
    confirm.open({
      title: "Update definitions",
      message: "Download antivirus definitions now? This acts immediately and does not stage or commit configuration.",
      confirmLabel: "Update definitions",
      onConfirm: () => void onRunUpdate(),
    });
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
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
          {canEdit && cfg.mode === "clamav" && (
            <button
              onClick={confirmUpdate}
              disabled={updating}
              className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
            >
              {updating ? "Updating\u2026" : "Run definition update"}
            </button>
          )}
          {canEdit && (
            <button
              onClick={onSave}
              disabled={!canSave || loading || save.pending !== null}
              className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
            >
              {save.pending ? "Saving\u2026" : "Save"}
            </button>
          )}
          <label className="ml-2 flex items-center gap-2 text-xs text-(--text)">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded-sm bg-(--surface)"
            />
            Auto
          </label>
        </div>
      }
    >
      <ServiceFaultBanner status={servicesStatus} loading={loading} only={["av"]} />
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice {...conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={editor.superseded} />
      <ServiceStatusStrip configured={canSave ? cfg.enabled : undefined} running={status?.available && effectiveMode(status.mode) === "clamav" ? status.clamav_running : undefined}
        attention={!status || !status.available ? "Live scanner status unavailable — use Refresh to retry" : status.last_error || status.ready_error || status.freshclam_error || status.fault?.message || (status.state === "faulted" ? "Service faulted" : undefined)}
        updated={status?.available ? status.last_render : undefined}
        summary={<GateSummary gate={status?.available ? status.gate : undefined} />} />
      {missingDatabase && (
        <div className="mb-4 rounded-xs border p-3 text-sm">
          <p>The local scanner needs signature databases before it can scan. Updating definitions acts immediately.</p>
          {canEdit && <button disabled={updating} onClick={confirmUpdate} className="mt-2 rounded-xs border px-3 py-2">Update definitions</button>}
        </div>
      )}
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {!loading && refreshError && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {refreshError}
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
          {error.includes("needs dataplane.enforcement") && (
            <p className="mt-2">Scanning needs firewall enforcement. <Link className="underline" href="/firewall/#enforcement">Stage enforcement on the Firewall page</Link>, then retry Save and review both changes before committing.</p>
          )}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>
      {updateMsg && (
        <div className="mb-4 rounded-lg border bg-(--surface) px-3 py-2 text-sm text-(--text)">
          {updateMsg}
        </div>
      )}

      {status?.available === false && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          Antivirus status unavailable: {status.error || "no response"}
        </div>
      )}
      {status?.available && status.state !== "faulted" && cfg.enabled !== status.enabled && (
        <div className="mb-4 rounded-lg border px-3 py-2 text-sm">
          Settings show AV {cfg.enabled ? "enabled" : "disabled"} but runtime reports {status.enabled ? "enabled" : "disabled"}. Save to stage your changes, then commit to apply.
        </div>
      )}

      <Card>
        <h2 className="text-lg font-semibold text-(--text)">Settings</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, enabled: e.target.checked }))}
              className="h-4 w-4"
            />
            Enable AV/ICAP scanning
          </label>
          <div>
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">Mode</label>
            <select
              value={cfg.mode}
              disabled={!canEdit || !canSave}
              onChange={(e) => {
                const mode = e.target.value as AVConfig["mode"];
                setCfg((c) => {
                  const next = { ...c, mode };
                  // Auto-populate required ClamAV defaults if switching to clamav mode
                  if (mode === "clamav") {
                    next.clamav = {
                      ...(c.clamav ?? {}),
                      socketPath: c.clamav?.socketPath || "/run/clamav/clamd.sock",
                    };
                  }
                  return next;
                });
              }}
              className="mt-1 w-full input-industrial"
            >
              <option value="clamav">Local scanner (ClamAV)</option>
              <option value="icap">Remote scanner (ICAP)</option>
            </select>
          </div>
          <div>
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">Fail policy</label>
            <select
              value={cfg.failPolicy ?? "open"}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, failPolicy: e.target.value as AVConfig["failPolicy"] }))}
              className="mt-1 w-full input-industrial"
            >
              <option value="open">Allow unscanned traffic when the scanner is unavailable</option>
              <option value="closed">Block selected traffic when the scanner is unavailable</option>
            </select>
          </div>
          <div>
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">Max size (bytes)</label>
            <input
              type="number"
              value={cfg.maxSizeBytes ?? 0}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, maxSizeBytes: Number(e.target.value) }))}
              className="mt-1 w-full input-industrial"
            />
          </div>
          <div>
            <label htmlFor="av-cache-ttl" className="text-xs uppercase tracking-wide text-(--text-muted)">Cache TTL (seconds)</label>
            <input
              id="av-cache-ttl"
              type="number"
              min="0"
              step="any"
              value={(cfg.cacheTtl ?? 0) / 1_000_000_000}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, cacheTtl: Math.round(Number(e.target.value) * 1_000_000_000) }))}
              className="mt-1 w-full input-industrial"
            />
            <p className="mt-1 text-xs text-(--text-muted)">Local scanner verdict cache duration. 0 uses 10 minutes; ICAP is never cached.</p>
          </div>
          <div>
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">Timeout (seconds)</label>
            <input
              type="number"
              value={cfg.timeoutSec ?? 0}
              disabled={!canEdit || !canSave}
              onChange={(e) => setCfg((c) => ({ ...c, timeoutSec: Number(e.target.value) }))}
              className="mt-1 w-full input-industrial"
            />
          </div>
        </div>
        <section className="mt-4">
          <h2 className="text-lg font-semibold text-(--text)">Scanned traffic</h2>
          <div className="mt-3">
            <ScanSelectionEditor cfg={cfg} update={setCfg} zones={zones} assets={assets} canEdit={canEdit && canSave} />
          </div>
        </section>
        <details className="mt-6 rounded-xs border p-3" open={cfg.mode === "icap" || icapServers.length > 0}>
          <summary className="cursor-pointer text-sm"><span>Advanced remote scanner settings</span>{(cfg.mode === "icap" || icapServers.length > 0) && <span className="ml-2 text-xs text-(--text-muted)">Configured settings</span>}</summary>
          <h3 className="text-sm font-semibold text-(--text)">ICAP servers</h3>
          <p className="text-xs text-(--text-muted)">Used when mode is ICAP: one RFC 3507 server (REQMOD for uploads, RESPMOD for downloads).</p>
          <div className="mt-3 space-y-2">
            {icapServers.map((srv, idx) => (
              <div key={idx} className="grid gap-2 rounded-lg border bg-(--surface) p-3 md:grid-cols-4">
                <input
                  value={srv.address}
                  onChange={(e) => updateICAPServer(idx, "address", e.target.value)}
                  disabled={!canEdit || !canSave}
                  placeholder="host:port"
                  className="input-industrial"
                />
                <input
                  value={srv.service ?? ""}
                  onChange={(e) => updateICAPServer(idx, "service", e.target.value)}
                  disabled={!canEdit || !canSave}
                  placeholder="service (optional)"
                  className="input-industrial"
                />
                <label className="flex items-center gap-2 text-sm text-(--text)">
                  <input
                    type="checkbox"
                    checked={srv.useTls ?? false}
                    disabled={!canEdit || !canSave}
                    onChange={(e) => updateICAPServer(idx, "useTls", e.target.checked)}
                    className="h-4 w-4"
                  />
                  TLS
                </label>
                {canEdit && (
                  <button
                    disabled={!canSave}
                    onClick={() => deleteICAPServer(idx)}
                    className="rounded-xs border px-3 py-2 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                  >
                    Delete
                  </button>
                )}
              </div>
            ))}
            {canEdit && icapServers.length === 0 && (
              <button
                disabled={!canSave}
                onClick={addICAPServer}
                className="rounded-xs border bg-(--surface2) px-3 py-2 text-sm text-(--text) transition-ui"
              >
                Add server
              </button>
            )}
          </div>
        </details>

        <details className="mt-6 rounded-xs border p-3" open={localScannerCustomized}>
          <summary className="cursor-pointer text-sm"><span>Advanced local scanner settings</span>{(localScannerCustomized) && <span className="ml-2 text-xs text-(--text-muted)">Configured settings</span>}</summary>
          <h3 className="text-sm font-semibold text-(--text)">ClamAV</h3>
          <p className="text-xs text-(--text-muted)">Used with the local scanner (ClamAV, the default).</p>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <div>
              <label className="text-xs uppercase tracking-wide text-(--text-muted)">Socket path</label>
              <input
                value={cfg.clamav?.socketPath ?? ""}
                disabled={!canEdit || !canSave}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), socketPath: e.target.value } }))
                }
                placeholder="/run/clamav/clamd.sock"
                className="mt-1 w-full input-industrial"
              />
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-(--text-muted)">Custom defs path</label>
              <input
                value={cfg.clamav?.customDefsPath ?? ""}
                disabled={!canEdit || !canSave}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), customDefsPath: e.target.value } }))
                }
                placeholder="/data/clamav/custom"
                className="mt-1 w-full input-industrial"
              />
            </div>
            <div>
              <label className="text-xs uppercase tracking-wide text-(--text-muted)">Update schedule</label>
              <input
                value={cfg.clamav?.updateSchedule ?? ""}
                disabled={!canEdit || !canSave}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), updateSchedule: e.target.value } }))
                }
                placeholder="Update interval, for example 4h"
                className="mt-1 w-full input-industrial"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-(--text)">
              <input
                type="checkbox"
                checked={cfg.clamav?.freshclamEnabled ?? false}
                disabled={!canEdit || !canSave}
                onChange={(e) =>
                  setCfg((c) => ({ ...c, clamav: { ...(c.clamav ?? {}), freshclamEnabled: e.target.checked } }))
                }
                className="h-4 w-4"
              />
              Enable definition auto-update
            </label>
          </div>
        </details>


      </Card>

      <SaveStateLine state={save.state} saved="staged — commit to apply." />
      <section aria-label="Immediate definition actions" className="my-4 rounded-xs border bg-(--surface) p-4">
        <h2 className="text-base font-semibold">Immediate definition actions</h2>
        <p className="mt-1 text-xs text-(--text-muted)">Run definition update, Upload file and Delete act immediately, independently of Save. Save only stages configuration.</p>
        <CustomDefinitions
          defs={defs}
          defsPath={defsPath}
          canEdit={canEdit}
          notify={(msg, ok) => {
            setUpdateMsg(msg);
            toast(msg, ok ? "success" : "error");
          }}
          refresh={refresh}
        />
      </section>
      <Card className="mb-4">
        <h2 className="text-base font-semibold text-(--text)">Activity</h2>
        <h3 className="text-sm font-semibold text-(--text)">Live runtime status</h3>
        {loading ? (
          <div className="mt-3 space-y-2">
            <Skeleton className="h-24 w-full" />
            <Skeleton className="h-10 w-1/2" />
          </div>
        ) : !status || !status.available ? (
          <p className="mt-3 text-sm text-(--text-muted)">Live scanner status was not reported.</p>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-3">
            <div>Enabled: <span className="text-(--text)">{typeof status?.enabled === "boolean" ? (status.enabled ? "yes" : "no") : "Unknown"}</span></div>
            <div>Scanner ready: <span className="text-(--text)">{typeof status?.ready !== "boolean" ? "Unknown" : status.ready ? "yes" : `no${status?.ready_error ? ` (${status.ready_error})` : ""}`}</span></div>
            <div>Detections: <span className="text-(--text)">{status?.detections ?? "Unknown"}</span></div>
            <div>Mode: <span className="text-(--text)">{effectiveMode(status.mode)}</span></div>
            <div>Fail policy: <span className="text-(--text)">{status?.failPolicy ?? "Unknown"}</span></div>
            <div>
              Rate: <span className="text-(--text)">{typeof status?.rate_per_min === "number" ? status.rate_per_min.toFixed(1) : "Unknown"} / min</span>
            </div>
            <div>
              Errors: <span>{typeof status?.errors_rate_per_min === "number" ? status.errors_rate_per_min.toFixed(1) : "Unknown"} / min</span>
            </div>

            {status.sparkline?.length ? (
              <div className="md:col-span-3">
                <Sparkline
                  values={status.sparkline}
                  color="var(--purple)"
                  background="linear-gradient(180deg, rgba(139,92,246,0.08), rgba(37,99,235,0.04))"
                  title="Scans per minute"
                />
              </div>
            ) : null}
            <div className="md:col-span-3 text-xs">{status?.last_error}</div>
            <div className="md:col-span-3 text-xs">{status?.freshclam_error}</div>
            <div className="md:col-span-3">
              <GateStatus gate={status.gate} />
            </div>
            <div className="md:col-span-3">
              <h3 className="text-sm">Troubleshooting</h3>
              <Disclosure title="Service details" indicator={!status.trust_revision || status.clamav_pid === undefined ? "Some details unknown" : undefined}>
              <div>Additional CA: <span className="text-(--text)">{status?.trust_revision || "Unknown"}</span></div>
              <div>Definitions: <span className="text-(--text)">{status?.db_version || "n/a"}</span></div>
              <div>ICAP servers: <span className="text-(--text)">{status?.icap_servers ?? "Unknown"}</span></div>
              <div>Cache: <span className="text-(--text)">{status?.cache_size ?? "Unknown"}</span></div>
              <div>ClamAV running: <span className="text-(--text)">{typeof status?.clamav_running !== "boolean" ? "Unknown" : status.clamav_running ? `yes (pid ${status?.clamav_pid ?? ""})` : "no"}</span></div>
              <div>ClamAV socket: <span className="text-(--text)">{status?.clamav_socket || "n/a"}</span></div>
              <div>ClamAV last start: <span className="text-(--text)">{status?.clamav_last_start || "Unknown"}</span></div>
              <div>Definition updater software: Freshclam</div>
              <div>Definition updater: <span className="text-(--text)">{typeof status?.freshclam_enabled !== "boolean" ? "Unknown" : status.freshclam_enabled ? (status?.freshclam_running ? "running" : "enabled") : "disabled"}</span></div>
              <div>Definition updater last: <span className="text-(--text)">{status?.freshclam_last || "Unknown"}</span></div>
              <div>Definition updater interval: <span className="text-(--text)">{status?.freshclam_interval || "Unknown"}</span></div>
              <div>Custom definition folder: <span className="text-(--text)">{defsPath || status?.clamav_custom_defs || cfg.clamav?.customDefsPath || "/data/clamav/custom"}</span></div>
            </Disclosure>
            </div>
          </div>
        )}
      </Card>
      <ConfirmDialog {...confirm.props} />
    </Shell>
  );
}
