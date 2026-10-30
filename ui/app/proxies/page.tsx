"use client";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigForm } from "../../lib/use-config-form";
import { useConfigEditor, ConfigEditNotice } from "../../lib/use-config-editor";

import { useConfigRefresh } from "../../lib/use-config-refresh";

import { useCallback, useEffect, useState } from "react";
import Image from "next/image";

import {
  api,
  isAdmin,
  type ForwardProxyConfig,
  type ReverseProxyConfig,
  type ReverseProxySite,
  type ServicesStatus,
} from "../../lib/api";
import { staticAssetURL } from "../../lib/api-core";
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
  const [status, setStatus] = useState<ServicesStatus | null>(null);
  const forwardDraft = useConfigEditor<ForwardProxyConfig>({
    enabled: false,
    listenPort: 3128,
    listenZones: ["mgmt"],
    allowedDomains: [],
    allowedClients: [],
    upstream: "",
    logRequests: false,
  });
  const reverseDraft = useConfigEditor<ReverseProxyConfig>({
    enabled: false,
    sites: [],
  });
  const siteDraft = useConfigForm({ site: {
    name: "",
    listenPort: 8081,
    hostnames: [],
    backends: [],
    tlsEnabled: false,
  } as ReverseProxySite, backends: "", hostnames: "" });
  const { cfg: forward, setCfg: setForward, adoptConfig: adoptForward } = forwardDraft;
  const { cfg: reverse, setCfg: setReverse, adoptConfig: adoptReverse } = reverseDraft;
  const [newSite, setNewSite] = siteDraft.field("site");
  const [backendsCSV, setBackendsCSV] = siteDraft.field("backends");
  const [hostnamesCSV, setHostnamesCSV] = siteDraft.field("hostnames");
  const { refreshForm: refreshSite } = siteDraft;
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    try {
      setStatus(await api.getServicesStatus());
      const fp = await api.getForwardProxy();
      setError(null);
      if (fp) {
        adoptForward({
          enabled: fp.enabled ?? false,
          listenPort: fp.listenPort ?? 3128,
          listenZones: fp.listenZones ?? [],
          allowedDomains: fp.allowedDomains ?? [],
          allowedClients: fp.allowedClients ?? [],
          upstream: fp.upstream ?? "",
          logRequests: fp.logRequests ?? false,
        }, keepEdits);
      }
      const rp = await api.getReverseProxy();
      if (rp) {
        adoptReverse({
          enabled: rp.enabled ?? false,
          sites: rp.sites ?? [],
        }, keepEdits);
      }
      refreshSite(rp, keepEdits);
      toast("Proxy status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to refresh proxies.");
      toast("Failed to refresh proxies", "error");
    }
  }, [toast, adoptForward, adoptReverse, refreshSite]));

  useConfigRefresh(refresh);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

  const listenZonesCSV = forwardDraft.text("listenZones", (forward.listenZones ?? []).join(", "));
  const allowedDomainsCSV = forwardDraft.text("allowedDomains", (forward.allowedDomains ?? []).join(", "));
  // Envoy and nginx report their own access-log meters next to the proxy
  // service entry.
  const proxy = status?.proxy;
  const envoy = status?.envoy;
  const nginx = status?.nginx;

  async function onSaveForward() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const submitted = forwardDraft.beginSave();
    const saved = await api.setForwardProxy({ ...forward,
      listenZones: listenZonesCSV.split(",").map((s) => s.trim()).filter(Boolean),
      allowedDomains: allowedDomainsCSV.split(",").map((s) => s.trim()).filter(Boolean),
    });
    setSaveState(saved.ok ? "saved" : "error");
    if (!saved.ok) {
      forwardDraft.failSave(submitted);
      const msg = saved.error || "Failed to save forward proxy settings.";
      setError(msg);
      toast(msg, "error");
    } else {
      forwardDraft.acceptConfig(submitted, saved.data);
      toast(saved.warning ? `Forward proxy staged — commit to apply. Warning: ${saved.warning}` : "Forward proxy staged — commit to apply.", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function onSaveReverse() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const submitted = reverseDraft.beginSave();
    const saved = await api.setReverseProxy(reverse);
    setSaveState(saved.ok ? "saved" : "error");
    if (!saved.ok) {
      reverseDraft.failSave(submitted);
      const msg = saved.error || "Failed to save reverse proxy settings.";
      setError(msg);
      toast(msg, "error");
    } else {
      reverseDraft.acceptConfig(submitted, saved.data);
      toast(saved.warning ? `Reverse proxy staged — commit to apply. Warning: ${saved.warning}` : "Reverse proxy staged — commit to apply.", "success");
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
    const backends = backendsCSV.split(",").map((s) => s.trim()).filter(Boolean);
    const hostnames = hostnamesCSV.split(",").map((s) => s.trim()).filter(Boolean);
    if (backends.length === 0) {
      setError("At least one backend is required.");
      return;
    }
    setReverse((r) => ({
      ...r,
      sites: [...(r.sites ?? []), { ...newSite, name: newSite.name.trim(), backends, hostnames }],
    }));
    siteDraft.acceptFields(siteDraft.editor, ["site", "backends", "hostnames"]);
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
            onClick={() => refresh({ keepEdits: false })}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Refresh
          </button>
          <label className="flex items-center gap-2 text-xs text-(--text)">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="h-4 w-4 rounded-sm bg-(--surface)"
            />
            Auto-refresh
          </label>
        </div>
      }
    >
      <ConfirmDialog {...confirm.props} />
      <ConfigEditNotice superseded={forwardDraft.editor.superseded || reverseDraft.editor.superseded || siteDraft.editor.superseded} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      <div className="mb-4 grid gap-4 md:grid-cols-2">
        <Card padding="lg" className="backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <Image src={staticAssetURL("/icons/envoyproxy.svg")} alt="" width={20} height={20} className="h-5 w-5" />
            <h2 className="text-sm font-semibold text-(--text)">Forward proxy (Envoy)</h2>
            <InfoTip label="Explicit forward proxy for outbound web traffic. Enable logging to emit request counts into telemetry." />
          </div>
          {loading ? (
            <div className="mt-3 space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-6 w-1/2" />
            </div>
          ) : (
            <>
              <p className="mt-2 text-xs text-(--text-muted)">
                Live running: {proxy?.envoy_running ? "yes" : "no"}{" "}
                {proxy?.envoy_pid ? `(pid ${proxy.envoy_pid})` : ""}
              </p>
              <p className="text-xs text-(--text-muted)">
                Rate: {(envoy?.rate_per_min ?? 0).toFixed(1)} / min
              </p>
              <p className="text-xs">
                Errors: {(envoy?.errors_rate_per_min ?? 0).toFixed(1)} / min
              </p>
              <p className="text-xs text-(--text-dim)">
                Telemetry: access logs when enabled.
              </p>
              {proxy?.envoy_last_error ? (
                <div className="mt-2 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {proxy.envoy_last_error}
                </div>
              ) : null}
              <p className="mt-2 text-xs text-(--text-muted)">
                Last start: {proxy?.envoy_last_start || "n/a"}
              </p>
              {envoy?.sparkline.length ? (
                <div className="mt-4">
                  <Sparkline
                    values={envoy.sparkline}
                    color="var(--primary)"
                    background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(139,92,246,0.05))"
                    title="Envoy events per minute"
                  />
                </div>
              ) : null}
            </>
          )}
        </Card>
        <Card padding="lg" className="backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <Image src={staticAssetURL("/icons/nginx.svg")} alt="" width={20} height={20} className="h-5 w-5" />
            <h2 className="text-sm font-semibold text-(--text)">Reverse proxy (Nginx)</h2>
            <InfoTip label="Publish internal apps with host/path routing and TLS termination." />
          </div>
          {loading ? (
            <div className="mt-3 space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-6 w-1/2" />
            </div>
          ) : (
            <>
              <p className="mt-2 text-xs text-(--text-muted)">
                Live running: {proxy?.nginx_running ? "yes" : "no"}{" "}
                {proxy?.nginx_pid ? `(pid ${proxy.nginx_pid})` : ""}
              </p>
              <p className="text-xs text-(--text-muted)">
                Rate: {(nginx?.rate_per_min ?? 0).toFixed(1)} / min
              </p>
              <p className="text-xs">
                Errors: {(nginx?.errors_rate_per_min ?? 0).toFixed(1)} / min
              </p>
              <p className="text-xs text-(--text-dim)">
                Telemetry: access logs from published apps.
              </p>
              {proxy?.nginx_last_error ? (
                <div className="mt-2 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
                  {proxy.nginx_last_error}
                </div>
              ) : null}
              <p className="mt-2 text-xs text-(--text-muted)">
                Last start: {proxy?.nginx_last_start || "n/a"}
              </p>
              {nginx?.sparkline.length ? (
                <div className="mt-4">
                  <Sparkline
                    values={nginx.sparkline}
                    color="var(--purple)"
                    background="linear-gradient(180deg, rgba(139,92,246,0.08), rgba(6,182,212,0.05))"
                    title="Nginx events per minute"
                  />
                </div>
              ) : null}
            </>
          )}
        </Card>
      </div>
      {!loading && error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "---"} {autoRefresh ? "(auto)" : ""}
      </p>

      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
          <h2 className="text-lg font-semibold text-(--text)">Forward proxy</h2>
          <p className="mt-1 text-sm text-(--text)">
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
                className="h-4 w-4 rounded-sm bg-(--surface)"
              />
              Enabled
            </label>

            <div>
              <label className="block text-sm font-medium text-(--text)">
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
                className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
              />
            </div>

            <details className="rounded-xs border bg-(--surface) px-4 py-3">
              <summary className="cursor-pointer text-sm text-(--text)">
                Advanced options
              </summary>
              <div className="mt-3 space-y-4">
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-(--text)">
                    Listen zones
                    <InfoTip label="Comma-separated zones where the proxy listens. Leave blank to bind on all." />
                  </label>
                  <input
                    type="text"
                    value={listenZonesCSV}
                    disabled={!canEdit}
                    onChange={(e) => forwardDraft.setText("listenZones", e.target.value)}
                    placeholder="mgmt, lan"
                    className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-(--text)">
                    Allowed domains
                    <InfoTip label="Comma-separated FQDN patterns (e.g. *.vendor.com). Use * to allow all." />
                  </label>
                  <input
                    type="text"
                    value={allowedDomainsCSV}
                    disabled={!canEdit}
                    onChange={(e) => forwardDraft.setText("allowedDomains", e.target.value)}
                    placeholder="*.example.com"
                    className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-(--text)">
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
                    className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
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
                className="h-4 w-4 rounded-sm bg-(--surface)"
              />
              Log requests
              <InfoTip label="Writes access logs so the UI can show request rate and errors." />
            </label>

            <div className="flex items-center justify-end gap-3">
              {saveState === "error" && (
                <span className="text-sm text-red-400">Save failed</span>
              )}
              {saveState === "saved" && (
                <span className="text-sm text-emerald-400">Staged — commit to apply.</span>
              )}
              {canEdit && (
                <button
                  onClick={onSaveForward}
                  disabled={saveState === "saving"}
                  className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                >
                  {saveState === "saving" ? "Saving..." : "Save"}
                </button>
              )}
            </div>
          </div>
        </section>

        <section className="rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
          <h2 className="text-lg font-semibold text-(--text)">Reverse proxy</h2>
          <p className="mt-1 text-sm text-(--text)">
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
                className="h-4 w-4 rounded-sm bg-(--surface)"
              />
              Enabled
            </label>

            <div className="rounded-xs border bg-(--surface) p-4">
              <h3 className="text-sm font-semibold text-(--text)">Add site</h3>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <input
                  type="text"
                  value={newSite.name}
                  disabled={!canEdit}
                  onChange={(e) =>
                    setNewSite((s) => ({ ...s, name: e.target.value }))
                  }
                  placeholder="site name"
                  className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
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
                  className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
                <input
                  type="text"
                  value={backendsCSV}
                  disabled={!canEdit}
                  onChange={(e) => setBackendsCSV(e.target.value)}
                  placeholder="backends host:port, host:port"
                  className="md:col-span-2 input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
                <input
                  type="text"
                  value={hostnamesCSV}
                  disabled={!canEdit}
                  onChange={(e) => setHostnamesCSV(e.target.value)}
                  placeholder="hostnames (optional)"
                  className="md:col-span-2 input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                />
              </div>
              <div className="mt-3 flex justify-end">
                {canEdit && (
                  <button
                    onClick={addSite}
                    className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui"
                  >
                    Add
                  </button>
                )}
              </div>
            </div>

            <div className="space-y-2">
              {(reverse.sites ?? []).length === 0 && (
                <div className="text-sm text-(--text-muted)">
                  No reverse proxy sites configured.
                </div>
              )}
              {(reverse.sites ?? []).map((site) => (
                <div
                  key={site.name}
                  className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2"
                >
                  <div>
                    <div className="text-sm font-semibold text-(--text)">
                      {site.name}
                    </div>
                    <div className="text-xs text-(--text-muted)">
                      port {site.listenPort} → {(site.backends ?? []).join(", ")}
                    </div>
                  </div>
                  {canEdit && (
                    <button
                      onClick={() => deleteSite(site.name)}
                      className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui"
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
                <span className="text-sm text-emerald-400">Staged — commit to apply.</span>
              )}
              {canEdit && (
                <button
                  onClick={onSaveReverse}
                  disabled={saveState === "saving"}
                  className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
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
