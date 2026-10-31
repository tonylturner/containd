"use client";

import { useAsyncRefresh } from "../../../../hooks/useAsyncRefresh";

import { useConfigEditor, ConfigEditNotice } from "../../../../lib/use-config-editor";

import { useConfigRefresh } from "../../../../lib/use-config-refresh";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";

import { api, isAdmin, type DNSConfig, type DNSStatus } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { SaveStateLine } from "../../../../components/SaveStateLine";
import { useSaveAction } from "../../../../hooks/useSaveAction";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { InfoTip } from "../../../../components/InfoTip";
import { Card } from "../../../../components/Card";

export default function DNSPage() {
  const canEdit = isAdmin();
  const [status, setStatus] = useState<DNSStatus | null>(null);
  const { editor, cfg, setCfg, adoptConfig, beginSave, failSave, acceptConfig, text, setText } = useConfigEditor<DNSConfig>({
    enabled: false,
    listenPort: 53,
    upstreamServers: [],
    cacheSizeMB: 0,
  });
  const save = useSaveAction();
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    const svc = await api.getServicesStatus();
    setStatus(svc?.dns ?? null);
    const s = await api.getDNS();
    adoptConfig({
      enabled: s?.enabled ?? false,
      listenPort: s?.listenPort ?? 53,
      listenZones: s?.listenZones ?? [],
      upstreamServers: s?.upstreamServers ?? [],
      cacheSizeMB: s?.cacheSizeMB ?? 0,
    }, keepEdits);
    setLastUpdated(new Date());
  }, [adoptConfig]));

  useConfigRefresh(refresh);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const upstreamText = text("upstreamServers", (cfg.upstreamServers ?? []).join("\n"));

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    const submitted = beginSave();
    const saved = await save.run("save", () => api.setDNS({ ...cfg, upstreamServers: upstreamText.split("\n").map((s) => s.trim()).filter(Boolean) }), {
      success: "DNS settings staged — commit to apply.",
      failure: "Failed to save DNS settings.",
    });
    if (!saved) { failSave(submitted); return; }
    if (saved.ok) acceptConfig(submitted, saved.data);
    else { failSave(submitted); setError(saved.error); }
    await refresh();
  }

  return (
    <Shell
      title="DNS"
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
              disabled={save.pending !== null}
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
      <ConfigEditNotice superseded={editor.superseded} />
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

      <div className="mb-4 flex items-center justify-between rounded-lg border bg-(--surface) px-3 py-2 text-xs text-(--text)">
        <span>Related LAN services</span>
        <Link href="/dhcp/" className="text-emerald-400 hover:text-emerald-400/80">
          DHCP server &rarr;
        </Link>
      </div>

      <Card className="mb-4">
        <h2 className="text-sm font-semibold text-(--text)">Live runtime status</h2>
        {loading ? (
          <div className="mt-3">
            <Skeleton className="h-20 w-full" />
          </div>
        ) : (
          <div className="mt-3 grid gap-2 text-sm text-(--text) md:grid-cols-2">
            <div>
              Installed:{" "}
              <span className="text-(--text)">
                {status?.installed ? "yes" : "no"}
              </span>
            </div>
            <div>
              Running:{" "}
              <span className="text-(--text)">{status?.running ? "yes" : "no"}</span>
              {status?.pid ? <span className="text-(--text-muted)"> (pid {status.pid})</span> : null}
            </div>
            <div>
              Rate: <span className="text-(--text)">{typeof status?.rate_per_min === "number" ? status?.rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div>
              Errors: <span>{typeof status?.errors_rate_per_min === "number" ? status?.errors_rate_per_min.toFixed(1) : "0.0"} / min</span>
            </div>
            <div className="md:col-span-2">
              Config:{" "}
              <span className="text-(--text)">
                {status?.config_path ?? "(unknown)"}
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
                  color="var(--primary)"
                  background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(139,92,246,0.05))"
                  title="DNS events per minute"
                />
              </div>
            ) : null}
          </div>
        )}
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-(--text)">Resolver</h2>
        <p className="mt-1 text-sm text-(--text)">
          Configure the embedded Unbound DNS resolver.
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
            Enable DNS resolver
            <InfoTip label="Runs the Unbound resolver on configured interfaces." />
          </label>

          <div className="md:col-span-2">
            <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
              Upstream Servers (one per line)
              <InfoTip label="Forward-only DNS servers used by Unbound for resolution." />
            </label>
            <textarea
              rows={5}
              value={upstreamText}
              disabled={!canEdit}
              onChange={(e) => setText("upstreamServers", e.target.value)}
              placeholder="1.1.1.1\n8.8.8.8"
              className="mt-1 w-full input-industrial"
            />
          </div>

          <details className="md:col-span-2 rounded-xs border bg-(--surface) px-4 py-3">
            <summary className="cursor-pointer text-sm text-(--text)">Advanced options</summary>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <div>
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
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
                <label className="flex items-center gap-2 text-xs uppercase tracking-wide text-(--text-muted)">
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

        <SaveStateLine state={save.state} saved="staged — commit to apply." />
      </Card>
    </Shell>
  );
}
