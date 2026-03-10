"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Image from "next/image";

import {
  api,
  isAdmin,
  type ForwardProxyConfig,
  type ReverseProxyConfig,
  type ReverseProxySite,
} from "../../lib/api";
import { Shell } from "../../components/Shell";
import { useToast } from "../../components/ToastProvider";
import { Skeleton } from "../../components/Skeleton";
import { Sparkline } from "../../components/Sparkline";
import { InfoTip } from "../../components/InfoTip";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { Card } from "../../components/Card";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function ProxiesPage() {
  const canEdit = isAdmin();
  const toast = useToast();
  const confirm = useConfirm();
  const [status, setStatus] = useState<any>(null);
  const [forward, setForward] = useState<ForwardProxyConfig>({
    enabled: false,
    listenPort: 3128,
    listenZones: ["mgmt"],
    allowedDomains: [],
    allowedClients: [],
    upstream: "",
    logRequests: false,
  });
  const [reverse, setReverse] = useState<ReverseProxyConfig>({
    enabled: false,
    sites: [],
  });
  const [newSite, setNewSite] = useState<ReverseProxySite>({
    name: "",
    listenPort: 8081,
    hostnames: [],
    backends: [],
    tlsEnabled: false,
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const svc = (await api.getServicesStatus()) as any;
      setStatus(svc?.proxy ?? null);
      const fp = await api.getForwardProxy();
      if (fp) {
        setForward({
          enabled: fp.enabled ?? false,
          listenPort: fp.listenPort ?? 3128,
          listenZones: fp.listenZones ?? [],
          allowedDomains: fp.allowedDomains ?? [],
          allowedClients: fp.allowedClients ?? [],
          upstream: fp.upstream ?? "",
          logRequests: fp.logRequests ?? false,
        });
      }
      const rp = await api.getReverseProxy();
      if (rp) {
        setReverse({
          enabled: rp.enabled ?? false,
          sites: rp.sites ?? [],
        });
      }
      toast("Proxy status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to refresh proxies.");
      toast("Failed to refresh proxies", "error");
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

  const listenZonesCSV = useMemo(
    () => (forward.listenZones ?? []).join(", "),
    [forward.listenZones],
  );
  const allowedDomainsCSV = useMemo(
    () => (forward.allowedDomains ?? []).join(", "),
    [forward.allowedDomains],
  );
  const forwardSpark = useMemo(() => {
    if (Array.isArray(status?.envoy?.sparkline) && status.envoy.sparkline.length) {
      return status.envoy.sparkline as number[];
    }
    if (Array.isArray(status?.sparkline) && status.sparkline.length) {
      return status.sparkline as number[];
    }
    return [8, 11, 12, forward.enabled ? 18 : 10, 16, 14, 20];
  }, [status, forward.enabled]);
  const reverseSpark = useMemo(() => {
    if (Array.isArray(status?.nginx?.sparkline) && status.nginx.sparkline.length) {
      return status.nginx.sparkline as number[];
    }
    if (Array.isArray(status?.sparkline) && status.sparkline.length) {
      return status.sparkline as number[];
    }
    return [4, 6, 9, reverse.sites?.length ? 14 : 8, 12, 10, 15];
  }, [status, reverse.sites?.length]);

  async function onSaveForward() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setForwardProxy(forward);
    setSaveState(saved ? "saved" : "error");
    if (!saved) {
      setError("Failed to save forward proxy settings.");
      toast("Failed to save forward proxy settings", "error");
    } else {
      toast("Forward proxy saved", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function onSaveReverse() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setReverseProxy(reverse);
    setSaveState(saved ? "saved" : "error");
    if (!saved) {
      setError("Failed to save reverse proxy settings.");
      toast("Failed to save reverse proxy settings", "error");
    } else {
      toast("Reverse proxy saved", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  function addSite() {
    if (!canEdit) return;
    setError(null);
    if (!newSite.name.trim()) {
      setError("Site name is required.");
      return;
    }
    if (!newSite.listenPort || newSite.listenPort <= 0) {
      setError("Listen port must be valid.");
      return;
    }
    if (!newSite.backends || newSite.backends.length === 0) {
      setError("At least one backend is required.");
      return;
    }
    setReverse((r) => ({
      ...r,
      sites: [...(r.sites ?? []), { ...newSite, name: newSite.name.trim() }],
    }));
    setNewSite({
      name: "",
      listenPort: 8081,
      hostnames: [],
      backends: [],
      tlsEnabled: false,
    });
  }

  function deleteSite(name: string) {
    if (!canEdit) return;
    confirm.open({
      title: "Delete site",
      message: `Remove reverse proxy site "${name}"? This change takes effect when you save.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: () => {
        setReverse((r) => ({
          ...r,
          sites: (r.sites ?? []).filter((s) => s.name !== name),
        }));
      },
    });
  }

  return (
    <Shell
      title="Proxies"
      actions={
        <div className="flex items-center gap-3">
          <button
            onClick={() => refresh()}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-[var(--text)]">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded border-amber-500/[0.15] bg-[var(--surface)]"
            />
            Auto-refresh
          </label>
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      {!canEdit && (
        <div className="mb-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3 text-sm text-[var(--text)]">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <div className="mb-4 grid gap-4 md:grid-cols-2">
        <Card padding="lg" className="backdrop-blur">
          <div className="flex items-center gap-3">
            <Image src="/icons/envoyproxy.svg" alt="" width={20} height={20} className="h-5 w-5" />
            <h2 className="text-sm font-semibold text-[var(--text)]">Forward proxy (Envoy)</h2>
            <InfoTip label="Explicit forward proxy for outbound web traffic. Enable logging to emit request counts into telemetry." />
          </div>
          {loading ? (
            <div className="mt-3 space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-6 w-1/2" />
            </div>
          ) : (
            <>
              <p className="mt-2 text-xs text-[var(--text-muted)]">
                Running: {status?.envoy_running ? "yes" : "no"}{" "}
                {status?.envoy_pid ? `(pid ${status.envoy_pid})` : ""}
              </p>
              <p className="text-xs text-[var(--text-muted)]">
                Rate: {typeof status?.envoy?.rate_per_min === "number" ? status?.envoy?.rate_per_min.toFixed(1) : "0.0"} / min
              </p>
              <p className="text-xs text-amber-300">
                Errors: {typeof status?.envoy?.errors_rate_per_min === "number" ? status?.envoy?.errors_rate_per_min.toFixed(1) : "0.0"} / min
              </p>
              <p className="text-xs text-[var(--text-dim)]">
                Telemetry: access logs when enabled.
              </p>
              {status?.envoy_last_error ? (
                <div className="mt-2 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {status.envoy_last_error}
                </div>
              ) : null}
              <p className="mt-2 text-xs text-[var(--text-muted)]">
                Last start: {status?.envoy_last_start ? String(status.envoy_last_start) : "n/a"}
              </p>
              <div className="mt-4">
                <Sparkline
                  values={forwardSpark}
                  color="var(--primary)"
                  background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(139,92,246,0.05))"
                  title="Recent forward proxy requests"
                />
              </div>
            </>
          )}
        </Card>
        <Card padding="lg" className="backdrop-blur">
          <div className="flex items-center gap-3">
            <Image src="/icons/nginx.svg" alt="" width={20} height={20} className="h-5 w-5" />
            <h2 className="text-sm font-semibold text-[var(--text)]">Reverse proxy (Nginx)</h2>
            <InfoTip label="Publish internal apps with host/path routing and TLS termination." />
          </div>
          {loading ? (
            <div className="mt-3 space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-6 w-1/2" />
            </div>
          ) : (
            <>
              <p className="mt-2 text-xs text-[var(--text-muted)]">
                Running: {status?.nginx_running ? "yes" : "no"}{" "}
                {status?.nginx_pid ? `(pid ${status.nginx_pid})` : ""}
              </p>
              <p className="text-xs text-[var(--text-muted)]">
                Rate: {typeof status?.nginx?.rate_per_min === "number" ? status?.nginx?.rate_per_min.toFixed(1) : "0.0"} / min
              </p>
              <p className="text-xs text-amber-300">
                Errors: {typeof status?.nginx?.errors_rate_per_min === "number" ? status?.nginx?.errors_rate_per_min.toFixed(1) : "0.0"} / min
              </p>
              <p className="text-xs text-[var(--text-dim)]">
                Telemetry: access logs from published apps.
              </p>
              {status?.nginx_last_error ? (
                <div className="mt-2 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {status.nginx_last_error}
                </div>
              ) : null}
              <p className="mt-2 text-xs text-[var(--text-muted)]">
                Last start: {status?.nginx_last_start ? String(status.nginx_last_start) : "n/a"}
              </p>
              <div className="mt-4">
                <Sparkline
                  values={reverseSpark}
                  color="var(--purple)"
                  background="linear-gradient(180deg, rgba(139,92,246,0.08), rgba(6,182,212,0.05))"
                  title="Recent reverse proxy requests"
                />
              </div>
            </>
          )}
        </Card>
      </div>
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-[var(--text-muted)]">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "---"} {autoRefresh ? "(auto)" : ""}
      </p>

      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card backdrop-blur">
          <h2 className="text-lg font-semibold text-[var(--text)]">Forward proxy</h2>
          <p className="mt-1 text-sm text-[var(--text)]">
            Quick controls for enablement and listening port.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={forward.enabled ?? false}
                disabled={!canEdit}
                onChange={(e) =>
                  setForward((f) => ({ ...f, enabled: e.target.checked }))
                }
                className="h-4 w-4 rounded border-amber-500/[0.15] bg-[var(--surface)]"
              />
              Enabled
            </label>

            <div>
              <label className="block text-sm font-medium text-[var(--text)]">
                Listen port
              </label>
              <input
                type="number"
                value={forward.listenPort ?? 3128}
                disabled={!canEdit}
                onChange={(e) =>
                  setForward((f) => ({
                    ...f,
                    listenPort: Number(e.target.value),
                  }))
                }
                className="mt-2 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>

            <details className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-4 py-3">
              <summary className="cursor-pointer text-sm text-[var(--text)]">
                Advanced options
              </summary>
              <div className="mt-3 space-y-4">
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-[var(--text)]">
                    Listen zones
                    <InfoTip label="Comma-separated zones where the proxy listens. Leave blank to bind on all." />
                  </label>
                  <input
                    type="text"
                    value={listenZonesCSV}
                    disabled={!canEdit}
                    onChange={(e) =>
                      setForward((f) => ({
                        ...f,
                        listenZones: e.target.value
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                      }))
                    }
                    placeholder="mgmt, lan"
                    className="mt-2 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-[var(--text)]">
                    Allowed domains
                    <InfoTip label="Comma-separated FQDN patterns (e.g. *.vendor.com). Use * to allow all." />
                  </label>
                  <input
                    type="text"
                    value={allowedDomainsCSV}
                    disabled={!canEdit}
                    onChange={(e) =>
                      setForward((f) => ({
                        ...f,
                        allowedDomains: e.target.value
                          .split(",")
                          .map((s) => s.trim())
                          .filter(Boolean),
                      }))
                    }
                    placeholder="*.example.com"
                    className="mt-2 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-[var(--text)]">
                    Upstream proxy
                    <InfoTip label="Optional upstream proxy URL for chaining (phased). Leave empty for direct egress." />
                  </label>
                  <input
                    type="text"
                    value={forward.upstream ?? ""}
                    disabled={!canEdit}
                    onChange={(e) =>
                      setForward((f) => ({
                        ...f,
                        upstream: e.target.value,
                      }))
                    }
                    placeholder="http://upstream:3128"
                    className="mt-2 w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                  />
                </div>
              </div>
            </details>

            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={forward.logRequests ?? false}
                disabled={!canEdit}
                onChange={(e) =>
                  setForward((f) => ({ ...f, logRequests: e.target.checked }))
                }
                className="h-4 w-4 rounded border-amber-500/[0.15] bg-[var(--surface)]"
              />
              Log requests
              <InfoTip label="Writes access logs so the UI can show request rate and errors." />
            </label>

            <div className="flex items-center justify-end gap-3">
              {saveState === "error" && (
                <span className="text-sm text-red-400">Save failed</span>
              )}
              {saveState === "saved" && (
                <span className="text-sm text-emerald-400">Saved</span>
              )}
              {canEdit && (
                <button
                  onClick={onSaveForward}
                  disabled={saveState === "saving"}
                  className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                >
                  {saveState === "saving" ? "Saving..." : "Save"}
                </button>
              )}
            </div>
          </div>
        </section>

        <section className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-5 shadow-card backdrop-blur">
          <h2 className="text-lg font-semibold text-[var(--text)]">Reverse proxy</h2>
          <p className="mt-1 text-sm text-[var(--text)]">
            Add sites to expose internal apps.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={reverse.enabled ?? false}
                disabled={!canEdit}
                onChange={(e) =>
                  setReverse((r) => ({ ...r, enabled: e.target.checked }))
                }
                className="h-4 w-4 rounded border-amber-500/[0.15] bg-[var(--surface)]"
              />
              Enabled
            </label>

            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4">
              <h3 className="text-sm font-semibold text-[var(--text)]">Add site</h3>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <input
                  type="text"
                  value={newSite.name}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setNewSite((s) => ({ ...s, name: e.target.value }))
                  }
                  placeholder="site name"
                  className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  type="number"
                  value={newSite.listenPort}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setNewSite((s) => ({
                      ...s,
                      listenPort: Number(e.target.value),
                    }))
                  }
                  placeholder="listen port"
                  className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  type="text"
                  value={(newSite.backends ?? []).join(", ")}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setNewSite((s) => ({
                      ...s,
                      backends: e.target.value
                        .split(",")
                        .map((v) => v.trim())
                        .filter(Boolean),
                    }))
                  }
                  placeholder="backends host:port, host:port"
                  className="md:col-span-2 input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
                <input
                  type="text"
                  value={(newSite.hostnames ?? []).join(", ")}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setNewSite((s) => ({
                      ...s,
                      hostnames: e.target.value
                        .split(",")
                        .map((v) => v.trim())
                        .filter(Boolean),
                    }))
                  }
                  placeholder="hostnames (optional)"
                  className="md:col-span-2 input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                />
              </div>
              <div className="mt-3 flex justify-end">
                {canEdit && (
                  <button
                    onClick={addSite}
                    className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-3 py-1.5 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                  >
                    Add
                  </button>
                )}
              </div>
            </div>

            <div className="space-y-2">
              {(reverse.sites ?? []).length === 0 && (
                <div className="text-sm text-[var(--text-muted)]">
                  No reverse proxy sites configured.
                </div>
              )}
              {(reverse.sites ?? []).map((site) => (
                <div
                  key={site.name}
                  className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2"
                >
                  <div>
                    <div className="text-sm font-semibold text-[var(--text)]">
                      {site.name}
                    </div>
                    <div className="text-xs text-[var(--text-muted)]">
                      port {site.listenPort} → {(site.backends ?? []).join(", ")}
                    </div>
                  </div>
                  {canEdit && (
                    <button
                      onClick={() => deleteSite(site.name)}
                      className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                    >
                      Delete
                    </button>
                  )}
                </div>
              ))}
            </div>

            <div className="flex items-center justify-end gap-3">
              {saveState === "error" && (
                <span className="text-sm text-red-400">Save failed</span>
              )}
              {saveState === "saved" && (
                <span className="text-sm text-emerald-400">Saved</span>
              )}
              {canEdit && (
                <button
                  onClick={onSaveReverse}
                  disabled={saveState === "saving"}
                  className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                >
                  {saveState === "saving" ? "Saving..." : "Save"}
                </button>
              )}
            </div>
          </div>
        </section>
      </div>
    </Shell>
  );
}
