"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type DNSConfig, type ServicesStatus } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { useToast } from "../../../../components/ToastProvider";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { InfoTip } from "../../../../components/InfoTip";
import { Card } from "../../../../components/Card";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function DNSPage() {
  const canEdit = isAdmin();
  const toast = useToast();
  const [status, setStatus] = useState<any>(null);
  const [cfg, setCfg] = useState<DNSConfig>({
    enabled: false,
    listenPort: 53,
    upstreamServers: [],
    cacheSizeMB: 0,
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    const svc = (await api.getServicesStatus()) as ServicesStatus | any;
    setStatus((svc as any)?.dns ?? null);
    const s = await api.getDNS();
    setCfg({
      enabled: s?.enabled ?? false,
      listenPort: s?.listenPort ?? 53,
      listenZones: s?.listenZones ?? [],
      upstreamServers: s?.upstreamServers ?? [],
      cacheSizeMB: s?.cacheSizeMB ?? 0,
    });
    setLastUpdated(new Date());
    setLoading(false);
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

  const upstreamText = useMemo(
    () => (cfg.upstreamServers ?? []).join("\n"),
    [cfg.upstreamServers],
  );
  const dnsSpark = useMemo(
    () => [4, 8, 6, (cfg.upstreamServers?.length ?? 1) + 6, 12, 9, 14],
    [cfg.upstreamServers],
  );

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setDNS(cfg);
    setSaveState(saved ? "saved" : "error");
    if (!saved) {
      setError("Failed to save DNS settings.");
      toast("Failed to save DNS settings", "error");
    } else {
      setCfg(saved);
      toast("DNS settings saved", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
    await refresh();
  }

  return (
    <Shell
      title="DNS"
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

      <div className="mb-4 flex items-center justify-between rounded-lg border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)]">
        <span>Related LAN services</span>
        <Link href="/dhcp/" className="text-emerald-400 hover:text-emerald-400/80">
          DHCP server &rarr;
        </Link>
      </div>

      <Card className="mb-4">
        <h2 className="text-sm font-semibold text-[var(--text)]">Runtime status</h2>
        {loading ? (
          <div className="mt-3">
            <Skeleton className="h-20 w-full" />
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-[var(--text)] md:grid-cols-2">
            <div>
              Installed:{" "}
              <span className="text-[var(--text)]">
                {status?.installed ? "yes" : "no"}
              </span>
            </div>
            <div>
              Running:{" "}
              <span className="text-[var(--text)]">{status?.running ? "yes" : "no"}</span>
              {status?.pid ? <span className="text-[var(--text-muted)]"> (pid {status.pid})</span> : null}
            </div>
            <div>
              Rate: <span className="text-[var(--text)]">{typeof status?.rate_per_min === "number" ? status?.rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>
              Errors: <span className="text-amber-300">{typeof status?.errors_rate_per_min === "number" ? status?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div className="md:col-span-2">
              Config:{" "}
              <span className="text-[var(--text)]">
                {status?.config_path ?? "(unknown)"}
              </span>
            </div>
            {status?.last_error ? (
              <div className="md:col-span-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {status.last_error}
              </div>
            ) : null}
            <div className="md:col-span-2">
              <Sparkline
                values={dnsSpark}
                color="var(--primary)"
                background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(139,92,246,0.05))"
                title="Resolver query trend"
              />
            </div>
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-[var(--text)]">Resolver</h2>
        <p className="mt-1 text-sm text-[var(--text)]">
          Configure the embedded Unbound DNS resolver.
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
            Enable DNS resolver
            <InfoTip label="Runs the Unbound resolver on configured interfaces." />
          </label>

          <div className="md:col-span-2">
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
              Upstream Servers (one per line)
              <InfoTip label="Forward-only DNS servers used by Unbound for resolution." />
            </label>
            <textarea
              rows={5}
              value={upstreamText}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  upstreamServers: e.target.value
                    .split("\n")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="1.1.1.1\n8.8.8.8"
              className="mt-1 w-full input-industrial"
            />
          </div>

          <details className="md:col-span-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
            <summary className="cursor-pointer text-sm text-[var(--text)]">Advanced options</summary>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Listen Port
                  <InfoTip label="Local port for the DNS resolver (default 53)." />
                </label>
                <input
                  type="number"
                  value={cfg.listenPort ?? 53}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setCfg((c) => ({ ...c, listenPort: Number(e.target.value) }))
                  }
                  className="mt-1 w-full input-industrial"
                />
              </div>

              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  Cache Size (MB)
                  <InfoTip label="In-memory cache size for DNS responses." />
                </label>
                <input
                  type="number"
                  value={cfg.cacheSizeMB ?? 0}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setCfg((c) => ({ ...c, cacheSizeMB: Number(e.target.value) }))
                  }
                  className="mt-1 w-full input-industrial"
                />
              </div>
            </div>
          </details>
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
