"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api, isAdmin, type NTPConfig } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { useToast } from "../../../../components/ToastProvider";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { Card } from "../../../../components/Card";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function NTPPage() {
  const canEdit = isAdmin();
  const toast = useToast();
  const [status, setStatus] = useState<any>(null);
  const [cfg, setCfg] = useState<NTPConfig>({
    enabled: false,
    servers: [],
    intervalSeconds: 0,
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    const svc = (await api.getServicesStatus()) as any;
    setStatus(svc?.ntp ?? null);
    const s = await api.getNTP();
    setCfg({
      enabled: s?.enabled ?? false,
      servers: s?.servers ?? [],
      intervalSeconds: s?.intervalSeconds ?? 0,
    });
    setLoading(false);
    setLastUpdated(new Date());
  }, []);

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

  const serversText = useMemo(
    () => (cfg.servers ?? []).join("\n"),
    [cfg.servers],
  );
  const ntpSpark = useMemo(
    () => [2, 3, 5, (cfg.servers?.length ?? 1) + 4, 6, 5, 7],
    [cfg.servers],
  );

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setNTP(cfg);
    setSaveState(saved ? "saved" : "error");
    if (!saved) {
      setError("Failed to save NTP settings.");
      toast("Failed to save NTP settings", "error");
    } else {
      toast("NTP settings saved", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
    if (saved) setCfg(saved);
  }

  return (
    <Shell
      title="NTP"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-1.5 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
          >
            Refresh
          </button>
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
      {!canEdit && (
        <div className="mb-4 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
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

      <Card className="mb-4">
        <h2 className="text-sm font-semibold text-white">Runtime status</h2>
        {loading ? (
          <div className="mt-3">
            <Skeleton className="h-20 w-full" />
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-slate-200 md:grid-cols-2">
            <div>
              Running:{" "}
              <span className="text-slate-100">{status?.running ? "yes" : "no"}</span>
              {status?.pid ? <span className="text-slate-400"> (pid {status.pid})</span> : null}
            </div>
            <div>
              Last start:{" "}
              <span className="text-slate-100">
                {status?.last_start ?? "n/a"}
              </span>
            </div>
            <div>
              Rate: <span className="text-slate-100">{typeof status?.rate_per_min === "number" ? status?.rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>
              Errors: <span className="text-amber-300">{typeof status?.errors_rate_per_min === "number" ? status?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div className="md:col-span-2">
              Binary:{" "}
              <span className="text-slate-100">
                {status?.openntpd_path || "not found"}
              </span>
            </div>
            {status?.last_error ? (
              <div className="md:col-span-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {status.last_error}
              </div>
            ) : null}
            <div className="md:col-span-2">
              <Sparkline
                values={ntpSpark}
                color="var(--teal)"
                background="linear-gradient(180deg, rgba(6,182,212,0.08), rgba(59,130,246,0.04))"
                title="NTP sync trend (simulated)"
              />
            </div>
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-white">Client</h2>
        <p className="mt-1 text-sm text-slate-300">
          Configure the embedded OpenNTPD client.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-slate-200">
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
            <label className="text-xs uppercase tracking-wide text-slate-400">
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
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-wide text-slate-400">
              Servers / Pools (one per line)
            </label>
            <textarea
              rows={5}
              value={serversText}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  servers: e.target.value
                    .split("\n")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="pool.ntp.org\n192.0.2.10"
              className="mt-1 w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>
        </div>

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
      </Card>
    </Shell>
  );
}
