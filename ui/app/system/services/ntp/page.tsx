"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api, isAdmin, type NTPConfig } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { useToast } from "../../../../components/ToastProvider";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";

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
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
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
        <div className="mb-4 rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-200">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-slate-400">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "—"} {autoRefresh ? "(auto)" : ""}
      </p>

      <div className="mb-4 rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
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
              <div className="md:col-span-2 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
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
      </div>

      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
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
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
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
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>
        </div>

        <p className="mt-3 text-xs text-slate-400">
          State:{" "}
          {saveState === "saving"
            ? "saving…"
            : saveState === "saved"
              ? "saved"
              : saveState === "error"
                ? "error"
                : "idle"}
        </p>
      </div>
    </Shell>
  );
}
