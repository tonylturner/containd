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
    setSaveState(saved.ok ? "saved" : "error");
    if (!saved.ok) {
      const msg = saved.error || "Failed to save NTP settings.";
      setError(msg);
      toast(msg, "error");
    } else {
      setCfg(saved.data);
      toast(saved.warning ? `NTP settings saved with warning: ${saved.warning}` : "NTP settings saved", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  return (
    <Shell
      title="NTP"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
          {canEdit && (
            <button
              onClick={onSave}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Save
            </button>
          )}
          <label className="ml-2 flex items-center gap-2 text-xs text-[var(--text)]">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded border-amber-500/[0.15] bg-[var(--surface)]"
            />
            Auto
          </label>
        </div>
      }
    >
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-[var(--text-muted)]">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>

      <Card className="mb-4">
        <h2 className="text-sm font-semibold text-[var(--text)]">Runtime status</h2>
        {loading ? (
          <div className="mt-3">
            <Skeleton className="h-20 w-full" />
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-[var(--text)] md:grid-cols-2">
            <div>
              Running:{" "}
              <span className="text-[var(--text)]">{status?.running ? "yes" : "no"}</span>
              {status?.pid ? <span className="text-[var(--text-muted)]"> (pid {status.pid})</span> : null}
            </div>
            <div>
              Last start:{" "}
              <span className="text-[var(--text)]">
                {status?.last_start ?? "n/a"}
              </span>
            </div>
            <div>
              Rate: <span className="text-[var(--text)]">{typeof status?.rate_per_min === "number" ? status?.rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>
              Errors: <span className="text-amber-300">{typeof status?.errors_rate_per_min === "number" ? status?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div className="md:col-span-2">
              Binary:{" "}
              <span className="text-[var(--text)]">
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
        <h2 className="text-lg font-semibold text-[var(--text)]">Client</h2>
        <p className="mt-1 text-sm text-[var(--text)]">
          Configure the embedded OpenNTPD client.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-[var(--text)]">
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
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
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
            <label className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
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
              className="mt-1 w-full input-industrial"
            />
          </div>
        </div>

        <p className="mt-3 text-xs text-[var(--text-muted)]">
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
