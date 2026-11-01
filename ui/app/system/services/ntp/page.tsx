"use client";

import { useAsyncRefresh } from "../../../../hooks/useAsyncRefresh";

import { revisionError, useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../../../lib/use-config-editor";

import { useConfigRefresh } from "../../../../lib/use-config-refresh";

import { useCallback, useEffect, useState } from "react";

import { api, isAdmin, type NTPConfig, type ServicesStatus } from "../../../../lib/api";
import { ServiceFaultBanner } from "../../../../components/ServiceFaultBanner";
import { Shell } from "../../../../components/Shell";
import { SaveStateLine } from "../../../../components/SaveStateLine";
import { useSaveAction } from "../../../../hooks/useSaveAction";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { ServiceDisclosure, ServiceStatusStrip } from "../service-presentation";
import { Card } from "../../../../components/Card";

export default function NTPPage() {
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const [servicesStatus, setServicesStatus] = useState<ServicesStatus | null>(null);
  const status = servicesStatus?.ntp ?? null;
  const { conflictProps, editor, cfg, setCfg, readConfig: adoptConfig, write, text, setText } = useConfigEditor<NTPConfig>({
    enabled: false,
    servers: [],
    intervalSeconds: 0,
  }, false);
  const save = useSaveAction();
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const svc = await api.getServicesStatus();
    setServicesStatus(svc);
    const sSnapshot = await api.getNTP();
    const s = (sSnapshot?.data ?? null);
    if (!checkLoaded(s)) return;
    setError(null);
    adoptConfig({ data: s, revision: sSnapshot?.revision ?? "" }, keepEdits);
    setLastUpdated(new Date());
  }, [adoptConfig, checkLoaded]));

  useConfigRefresh(refresh);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const serversText = text("servers", (cfg.servers ?? []).join("\n"));

  async function onSave() {
    if (!canEdit || !canSave || loading) return;
    setError(null);
    const saved = await save.run("save", () => write((base, submitted) => api.setNTP(base, { ...submitted, servers: serversText.split("\n").map((s) => s.trim()).filter(Boolean) }), { replace: data => data }), {
      success: "NTP settings staged — commit to apply.",
      failure: "Failed to save NTP settings.",
    });
    if (!saved) return;
    if (!saved.ok) setError(revisionError(saved));
  }

  return (
    <Shell
      title="NTP"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
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
      <ServiceFaultBanner status={servicesStatus} loading={loading} only={["ntp"]} />
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice {...conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={editor.superseded} />
      <ServiceStatusStrip configured={canSave ? cfg.enabled : undefined} running={status?.running}
        attention={!status ? "Live service status unavailable — use Refresh to retry" : status.last_error || status.fault?.message || (status.state === "faulted" ? "Service faulted" : undefined)}
        updated={status?.last_render} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>

      <Card>
        <h2 className="text-lg font-semibold text-(--text)">Client</h2>
        <p className="mt-1 text-sm text-(--text)">
          Synchronize appliance time using the configured NTP servers.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              disabled={!canEdit || !canSave}
              onChange={(e) =>
                setCfg((c) => ({ ...c, enabled: e.target.checked }))
              }
              className="h-4 w-4"
            />
            Enable NTP client
          </label>

          <details className="rounded-xs border p-3" open={(cfg.intervalSeconds ?? 0) > 0}>
            <summary className="cursor-pointer text-sm"><span>Advanced timing</span>{((cfg.intervalSeconds ?? 0) > 0) && <span className="ml-2 text-xs text-(--text-muted)">Configured settings</span>}</summary>
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">
              Requested polling interval (seconds)
            </label>
            <input
              type="number"
              value={cfg.intervalSeconds ?? 0}
              disabled={!canEdit || !canSave}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  intervalSeconds: Number(e.target.value),
                }))
              }
              className="mt-1 w-full input-industrial"
            />
            <p className="mt-2 text-xs text-(--text-muted)">Zero uses adaptive polling. Positive requests are rounded up to a power of two and limited to 16–131072 seconds; this is not a measured synchronization interval.</p>
          </details>

          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">
              Servers / Pools (one per line)
            </label>
            <textarea
              rows={5}
              value={serversText}
              disabled={!canEdit || !canSave}
              onChange={(e) => setText("servers", e.target.value)}
              placeholder="pool.ntp.org\n192.0.2.10"
              className="mt-1 w-full input-industrial"
            />
          </div>
        </div>

        <SaveStateLine state={save.state} saved="staged — commit to apply." />
      </Card>
      <Card className="mb-4">
        <h2 className="text-base font-semibold text-(--text)">Activity</h2>
        <h3 className="text-sm font-semibold text-(--text)">Live runtime status</h3>
        {loading ? (
          <div className="mt-3">
            <Skeleton className="h-20 w-full" />
          </div>
        ) : !status ? (
          <div role="status" className="mt-3 text-sm text-(--text-muted)">
            Unknown — live service status unavailable.
            <button type="button" onClick={() => refresh()} className="ml-2 underline">Retry</button>
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-2">
            <div>
              Running:{" "}
              <span className="text-(--text)">{typeof status?.running === "boolean" ? (status.running ? "yes" : "no") : "Unknown"}</span>
            </div>
            <div>
              Rate: <span className="text-(--text)">{typeof status?.rate_per_min === "number" ? status.rate_per_min.toFixed(1) : "Unknown"} / min</span>
            </div>
            <div>
              Errors: <span>{typeof status?.errors_rate_per_min === "number" ? status.errors_rate_per_min.toFixed(1) : "Unknown"} / min</span>
            </div>

            {status?.last_error ? (
              <div className="md:col-span-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {status.last_error}
              </div>
            ) : null}
            {status?.sparkline?.length ? (
              <div className="md:col-span-2">
                <Sparkline
                  values={status.sparkline}
                  color="var(--teal)"
                  background="linear-gradient(180deg, rgba(6,182,212,0.08), rgba(59,130,246,0.04))"
                  title="NTP events per minute"
                />
              </div>
            ) : null}
            <div className="md:col-span-2">
              <h3 className="text-sm">Troubleshooting</h3>
              <ServiceDisclosure title="Service details" indicator={status.ntpd_path === "" ? "Binary not found" : status.pid === undefined || !status.ntpd_path ? "Some details unknown" : undefined}>
              <p>Software: chrony</p>
              <p>Process ID: {status.pid ?? "Unknown"}</p>
              <div>
                Last start:{" "}
                <span className="text-(--text)">
                  {status?.last_start || "Unknown"}
                </span>
              </div>
              <div className="md:col-span-2">
                Binary:{" "}
                <span className="text-(--text)">
                  {status.ntpd_path === "" ? "not found" : status.ntpd_path ?? "Unknown"}{status.ntpd_name ? ` (${status.ntpd_name})` : ""}
                </span>
              </div>
            </ServiceDisclosure>
            </div>
          </div>
        )}
      </Card>
    </Shell>
  );
}
