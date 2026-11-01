"use client";

import { useAsyncRefresh } from "../../../../hooks/useAsyncRefresh";

import { useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../../../lib/use-config-editor";

import { useConfigRefresh } from "../../../../lib/use-config-refresh";

import { useCallback, useEffect, useState } from "react";

import { api, isAdmin, type NTPConfig, type NTPStatus } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { SaveStateLine } from "../../../../components/SaveStateLine";
import { useSaveAction } from "../../../../hooks/useSaveAction";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { Card } from "../../../../components/Card";

export default function NTPPage() {
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const [status, setStatus] = useState<NTPStatus | null>(null);
  const { conflictProps, editor, cfg, setCfg, adoptConfig, beginSave, failSave, acceptConfig, text, setText } = useConfigEditor<NTPConfig>({
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
    setStatus(svc?.ntp ?? null);
    const sSnapshot = await api.getNTP();
    const s = (sSnapshot?.data ?? null);
    if (!checkLoaded(s)) return;
    setError(null);
    adoptConfig(s, keepEdits, sSnapshot?.revision);
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
    const submitted = beginSave();
    const saved = await save.run("save", () => api.setNTP(submitted.baseRevision ?? "", { ...cfg, servers: serversText.split("\n").map((s) => s.trim()).filter(Boolean) }), {
      success: "NTP settings staged — commit to apply.",
      failure: "Failed to save NTP settings.",
    });
    if (!saved) { failSave(submitted); return; }
    if (saved.ok) acceptConfig(submitted, saved.data, saved.revision);
    else { failSave(submitted, saved); setError(saved.error); }
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
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice {...conflictProps} onReload={() => refresh({ keepEdits: false })} superseded={editor.superseded} />
      <fieldset disabled={!canSave} className="min-w-0">
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

      <Card className="mb-4">
        <h2 className="text-sm font-semibold text-(--text)">Live runtime status</h2>
        {loading ? (
          <div className="mt-3">
            <Skeleton className="h-20 w-full" />
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-2">
            <div>
              Running:{" "}
              <span className="text-(--text)">{status?.running ? "yes" : "no"}</span>
              {status?.pid ? <span className="text-(--text-muted)"> (pid {status.pid})</span> : null}
            </div>
            <div>
              Last start:{" "}
              <span className="text-(--text)">
                {status?.last_start || "never"}
              </span>
            </div>
            <div>
              Rate: <span className="text-(--text)">{typeof status?.rate_per_min === "number" ? status?.rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>
              Errors: <span>{typeof status?.errors_rate_per_min === "number" ? status?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div className="md:col-span-2">
              Binary:{" "}
              <span className="text-(--text)">
                {status?.ntpd_path || "not found"}{status?.ntpd_name ? ` (${status.ntpd_name})` : ""}
              </span>
            </div>
            {status?.last_error ? (
              <div className="md:col-span-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {status.last_error}
              </div>
            ) : null}
            {status?.sparkline.length ? (
              <div className="md:col-span-2">
                <Sparkline
                  values={status.sparkline}
                  color="var(--teal)"
                  background="linear-gradient(180deg, rgba(6,182,212,0.08), rgba(59,130,246,0.04))"
                  title="NTP events per minute"
                />
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-(--text)">Client</h2>
        <p className="mt-1 text-sm text-(--text)">
          Configure the embedded chrony NTP client.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-(--text)">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({ ...c, enabled: e.target.checked }))
              }
              className="h-4 w-4"
            />
            Enable NTP client
          </label>

          <div>
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">
              Interval Seconds (hint)
            </label>
            <input
              type="number"
              value={cfg.intervalSeconds ?? 0}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  intervalSeconds: Number(e.target.value),
                }))
              }
              className="mt-1 w-full input-industrial"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-wide text-(--text-muted)">
              Servers / Pools (one per line)
            </label>
            <textarea
              rows={5}
              value={serversText}
              disabled={!canEdit}
              onChange={(e) => setText("servers", e.target.value)}
              placeholder="pool.ntp.org\n192.0.2.10"
              className="mt-1 w-full input-industrial"
            />
          </div>
        </div>

        <SaveStateLine state={save.state} saved="staged — commit to apply." />
      </Card>
      </fieldset>
    </Shell>
  );
}
