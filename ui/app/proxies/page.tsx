"use client";

import { revisionError } from "../../lib/config-revision";

import { useAsyncRefresh } from "../../hooks/useAsyncRefresh";

import { useConfigForm } from "../../lib/use-config-form";
import { useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../lib/use-config-editor";

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
import { ProxyStatus } from "./proxy-status";
import { ReverseSiteForm } from "./reverse-site-form";
import { Disclosure } from "../../components/Disclosure";
import { Card } from "../../components/Card";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function ProxiesPage() {
  const canEdit = isAdmin();
  const { canSave, canSaveNow, loadError, checkLoaded } = useConfigLoad();
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
  }, false);
  const reverseDraft = useConfigEditor<ReverseProxyConfig>({
    enabled: false,
    sites: [],
  }, false);
  const siteDraft = useConfigForm({ site: {
    name: "",
    listenPort: 8081,
    hostnames: [],
    backends: [],
    tlsEnabled: false,
  } as ReverseProxySite, backends: "", hostnames: "", editingSite: null as string | null });
  const { cfg: forward, setCfg: setForward, readConfig: adoptForward } = forwardDraft;
  const { cfg: reverse, setCfg: setReverse, readConfig: adoptReverse } = reverseDraft;
  const [newSite, setNewSite] = siteDraft.field("site");
  const [editingSite, setEditingSite] = siteDraft.field("editingSite");
  const [backendsCSV, setBackendsCSV] = siteDraft.field("backends");
  const [hostnamesCSV, setHostnamesCSV] = siteDraft.field("hostnames");
  const { readConfig: refreshSite } = siteDraft;
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    try {
      setStatus(await api.getServicesStatus());
      const fpSnapshot = await api.getForwardProxy();
      const fp = (fpSnapshot?.data ?? null);
      const rpSnapshot = await api.getReverseProxy();
      const rp = (rpSnapshot?.data ?? null);
      if (!checkLoaded(fp) || !checkLoaded(rp)) return;
      setError(null);
      adoptForward({ data: fp, revision: fpSnapshot?.revision ?? "" }, keepEdits);
      adoptReverse({ data: rp, revision: rpSnapshot?.revision ?? "" }, keepEdits);
      refreshSite({ data: rp, revision: rpSnapshot?.revision ?? "" }, keepEdits);
      toast("Proxy status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      checkLoaded(null);
      setError(e instanceof Error ? e.message : "Failed to refresh proxies.");
      toast("Failed to refresh proxies", "error");
    }
  }, [checkLoaded, toast, adoptForward, adoptReverse, refreshSite]));

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
    if (!canEdit || !canSave || loading) return;
    setError(null);
    setSaveState("saving");
    const saved = await forwardDraft.write((base, submitted) => api.setForwardProxy(base, { ...submitted,
      listenZones: listenZonesCSV.split(",").map((s) => s.trim()).filter(Boolean),
      allowedDomains: allowedDomainsCSV.split(",").map((s) => s.trim()).filter(Boolean),
    }), { replace: data => data });
    setSaveState(saved.ok ? "saved" : revisionError(saved) === null ? "idle" : "error");
    if (!saved.ok) {
      const msg = revisionError(saved);
      setError(msg);
      if (msg) toast(msg, "error");
    } else {
      toast(saved.warning ? `Forward proxy staged — commit to apply. Warning: ${saved.warning}` : "Forward proxy staged — commit to apply.", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function onSaveReverse() {
    if (!canEdit || !canSave || loading) return;
    setError(null);
    setSaveState("saving");
    const saved = await reverseDraft.write((base, submitted) => api.setReverseProxy(base, submitted), { replace: data => data });
    setSaveState(saved.ok ? "saved" : revisionError(saved) === null ? "idle" : "error");
    if (!saved.ok) {
      const msg = revisionError(saved);
      setError(msg);
      if (msg) toast(msg, "error");
    } else {
      toast(saved.warning ? `Reverse proxy staged — commit to apply. Warning: ${saved.warning}` : "Reverse proxy staged — commit to apply.", "success");
    }
    setTimeout(() => setSaveState("idle"), 1500);
  }

  function addSite() {
    if (!canEdit || !canSave || loading) return;
    setError(null);
    if (!newSite.name.trim()) {
      setError("Site name is required.");
      return;
    }
    if (!Number.isInteger(newSite.listenPort) || newSite.listenPort < 1 || newSite.listenPort > 65535) {
      setError("Listen port must be valid.");
      return;
    }
    if ((reverse.sites ?? []).some(site => site.name === newSite.name.trim() && site.name !== editingSite)) {
      setError("Site name is already in use.");
      return;
    }
    if (newSite.tlsEnabled && !newSite.certRef?.trim()) {
      setError("Certificate reference is required when TLS is enabled.");
      return;
    }
    const backends = backendsCSV.split(",").map((s) => s.trim()).filter(Boolean);
    const hostnames = hostnamesCSV.split(",").map((s) => s.trim()).filter(Boolean);
    if (backends.length === 0) {
      setError("At least one backend is required.");
      return;
    }
    if (siteDraft.editor.baseRevision !== reverseDraft.editor.baseRevision) {
      siteDraft.requireReview(reverseDraft.editor.baseRevision ?? "");
      return;
    }
    if (editingSite !== null && !(reverse.sites ?? []).some(site => site.name === editingSite)) {
      setError("The site being edited is no longer in the local list. Cancel the edit and review the sites.");
      return;
    }
    const next = { ...newSite, name: newSite.name.trim(), certRef: newSite.certRef?.trim(), backends, hostnames };
    setReverse((r) => ({
      ...r,
      sites: editingSite === null ? [...(r.sites ?? []), next]
        : (r.sites ?? []).map(site => site.name === editingSite ? next : site),
    }));
    cancelSiteEdit();
  }

  function cancelSiteEdit() {
    setError(null);
    siteDraft.clearFields(siteDraft.editor.cfg.fields, ["site", "backends", "hostnames", "editingSite"]);
  }

  function editSite(site: ReverseProxySite) {
    if (!canEdit || !canSave) return;
    setError(null);
    setEditingSite(site.name);
    setNewSite({ ...site });
    setBackendsCSV((site.backends ?? []).join(", "));
    setHostnamesCSV((site.hostnames ?? []).join(", "));
  }

  function deleteSite(name: string) {
    if (!canEdit || !canSave) return;
    confirm.open({
      title: "Delete site",
      message: `Remove reverse proxy site "${name}"? This removes it from local edits only. Save to stage the removal, then commit to apply.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: () => {
        if (!canSaveNow()) return;
        if (editingSite === name) cancelSiteEdit();
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
      <ConfigEditNotice superseded={false} {...forwardDraft.conflictProps} onReload={() => refresh({ keepEdits: false })} />
      <ConfigEditNotice superseded={false} {...siteDraft.conflictProps} onReload={() => refresh({ keepEdits: false })} />
      <ConfigEditNotice superseded={false} {...reverseDraft.conflictProps} onReload={() => refresh({ keepEdits: false })} />
      <ConfirmDialog {...confirm.props} />
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice superseded={forwardDraft.editor.superseded || reverseDraft.editor.superseded || siteDraft.editor.superseded} />
      <ProxyStatus label="Forward proxy status" configured={canSave ? forward.enabled : undefined}
        running={proxy?.envoy_running} available={!!proxy} updated={proxy?.last_render}
        diagnostic={proxy?.envoy_last_error || proxy?.fault?.message} faulted={proxy?.state === "faulted"} />
      <ProxyStatus label="Reverse proxy status" configured={canSave ? reverse.enabled : undefined}
        running={proxy?.nginx_running} available={!!proxy} updated={proxy?.last_render}
        diagnostic={proxy?.nginx_last_error || proxy?.fault?.message} faulted={proxy?.state === "faulted"} />
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {!loading && error && (
        <div role="alert" className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "---"} {autoRefresh ? "(auto)" : ""}
      </p>

      <div className="grid min-w-0 gap-6 md:grid-cols-2">
        <section className="min-w-0 rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
          <h2 className="text-lg font-semibold text-(--text)">Forward proxy</h2>
          <p className="mt-1 text-sm text-(--text)">
            Quick controls for enablement and listening port.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={forward.enabled ?? false}
                disabled={!canEdit || !canSave}
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
                disabled={!canEdit || !canSave}
                onChange={(e) =>
                  setForward((f) => ({
                    ...f,
                    listenPort: Number(e.target.value),
                  }))
                }
                className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
              />
            </div>

            <details className="rounded-xs border bg-(--surface) px-4 py-3" open={(forward.listenZones ?? []).join(",") !== "mgmt" || !!forward.allowedDomains?.length || !!forward.upstream}>
              <summary className="cursor-pointer text-sm text-(--text)"><span>Advanced options</span>{((forward.listenZones ?? []).join(",") !== "mgmt" || !!forward.allowedDomains?.length || !!forward.upstream) && <span className="ml-2 text-xs text-(--text-muted)">Configured settings</span>}</summary>
              <div className="mt-3 space-y-4">
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-(--text)">
                    Listen zones
                    <InfoTip label="Comma-separated zones where the proxy listens. Leave blank to bind on all." />
                  </label>
                  <input
                    type="text"
                    value={listenZonesCSV}
                    disabled={!canEdit || !canSave}
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
                    disabled={!canEdit || !canSave}
                    onChange={(e) => forwardDraft.setText("allowedDomains", e.target.value)}
                    placeholder="*.example.com"
                    className="mt-2 w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium text-(--text)">
                    Upstream proxy
                    <InfoTip label="Upstream chaining is not supported. Leave this empty; nonempty values cannot be saved." />
                  </label>
                  <input
                    type="text"
                    value={forward.upstream ?? ""}
                    disabled={!canEdit || !canSave}
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
                disabled={!canEdit || !canSave}
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
                  disabled={!canSave || loading || saveState === "saving"}
                  className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                >
                  {saveState === "saving" ? "Saving..." : "Save"}
                </button>
              )}
            </div>
          </div>
        </section>

        <section className="min-w-0 rounded-xs border bg-(--surface) p-5 shadow-card backdrop-blur-sm">
          <h2 className="text-lg font-semibold text-(--text)">Reverse proxy</h2>
          <p className="mt-1 text-sm text-(--text)">
            Add sites to expose internal apps.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={reverse.enabled ?? false}
                disabled={!canEdit || !canSave}
                onChange={(e) =>
                  setReverse((r) => ({ ...r, enabled: e.target.checked }))
                }
                className="h-4 w-4 rounded-sm bg-(--surface)"
              />
              Enabled
            </label>

            <ReverseSiteForm site={newSite} setSite={setNewSite} backends={backendsCSV} setBackends={setBackendsCSV}
              hostnames={hostnamesCSV} setHostnames={setHostnamesCSV} editing={editingSite !== null}
              disabled={!canEdit || !canSave || loading || saveState === "saving"}
              onAccept={addSite} onCancel={cancelSiteEdit} />

            <div className="space-y-2">
              {(reverse.sites ?? []).length === 0 && (
                <div className="text-sm text-(--text-muted)">
                  No reverse proxy sites configured.
                </div>
              )}
              {(reverse.sites ?? []).map((site) => (
                <div
                  key={site.name}
                  className="flex min-w-0 flex-wrap items-center justify-between gap-3 rounded-xs border bg-(--surface) px-3 py-2"
                >
                  <div className="min-w-0 break-all">
                    <div className="text-sm font-semibold text-(--text)">
                      {site.name}
                    </div>
                    <div className="text-xs text-(--text-muted)">
                      port {site.listenPort} → {(site.backends ?? []).join(", ")}
                    </div>
                    <p className="text-xs text-(--text-muted)">TLS: {site.tlsEnabled ? "enabled" : "disabled"}{site.certRef ? ` · Certificate: ${site.certRef}` : ""}</p>
                    {site.description && <p className="text-xs text-(--text-muted)">{site.description}</p>}
                  </div>
                  {canEdit && (
                    <div className="flex shrink-0 gap-2">
                      <button disabled={!canSave || loading || saveState === "saving"} onClick={() => editSite(site)}
                        className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui">Edit</button>
                      <button
                        disabled={!canSave || loading || saveState === "saving"}
                        onClick={() => deleteSite(site.name)}
                        className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui"
                      >
                        Delete
                      </button>
                    </div>
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
                  disabled={!canSave || loading || saveState === "saving"}
                  className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-50"
                >
                  {saveState === "saving" ? "Saving..." : "Save"}
                </button>
              )}
            </div>
          </div>
        </section>
      </div>
      <h2 className="mt-6 text-lg font-semibold">Activity</h2>
      <div className="mb-4 grid gap-4 md:grid-cols-2">
        <Card padding="lg" className="backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <Image src={staticAssetURL("/icons/envoyproxy.svg")} alt="" width={20} height={20} className="h-5 w-5" />
            <h2 className="text-sm font-semibold text-(--text)">Forward proxy</h2>
            <InfoTip label="Explicit forward proxy for outbound web traffic. Enable logging to report request counts." />
          </div>
          {loading ? (
            <div className="mt-3 space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-6 w-1/2" />
            </div>
          ) : !proxy ? (
            <div role="status" className="mt-3 text-sm text-(--text-muted)">
              Unknown — live proxy status unavailable.
              <button type="button" onClick={() => refresh()} className="ml-2 underline">Retry</button>
            </div>
          ) : (
            <>
              <p className="mt-2 text-xs text-(--text-muted)">
                Live running: {typeof proxy?.envoy_running === "boolean" ? (proxy.envoy_running ? "yes" : "no") : "Unknown"}{" "}
              </p>
              <p className="text-xs text-(--text-muted)">
                Rate: {typeof envoy?.rate_per_min === "number" ? envoy.rate_per_min.toFixed(1) : "Unknown"} / min
              </p>
              <p className="text-xs">
                Errors: {typeof envoy?.errors_rate_per_min === "number" ? envoy.errors_rate_per_min.toFixed(1) : "Unknown"} / min
              </p>
              <p className="text-xs text-(--text-dim)">
                Activity source: access logs when enabled.
              </p>
              <h3 className="mt-3 text-sm">Troubleshooting</h3><Disclosure title="Service details" indicator={proxy.envoy_pid === undefined || !proxy.envoy_last_start ? "Some details unknown" : undefined}>
                <p>Software: Envoy</p>
                <p>Process ID: {proxy?.envoy_pid ?? "Unknown"}</p>
                <p>Last start: {proxy?.envoy_last_start || "n/a"}</p>
              </Disclosure>
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
            <h2 className="text-sm font-semibold text-(--text)">Reverse proxy</h2>
            <InfoTip label="Publish internal apps with host/path routing and TLS termination." />
          </div>
          {loading ? (
            <div className="mt-3 space-y-2">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-6 w-1/2" />
            </div>
          ) : !proxy ? (
            <div role="status" className="mt-3 text-sm text-(--text-muted)">
              Unknown — live proxy status unavailable.
              <button type="button" onClick={() => refresh()} className="ml-2 underline">Retry</button>
            </div>
          ) : (
            <>
              <p className="mt-2 text-xs text-(--text-muted)">
                Live running: {typeof proxy?.nginx_running === "boolean" ? (proxy.nginx_running ? "yes" : "no") : "Unknown"}{" "}
              </p>
              <p className="text-xs text-(--text-muted)">
                Rate: {typeof nginx?.rate_per_min === "number" ? nginx.rate_per_min.toFixed(1) : "Unknown"} / min
              </p>
              <p className="text-xs">
                Errors: {typeof nginx?.errors_rate_per_min === "number" ? nginx.errors_rate_per_min.toFixed(1) : "Unknown"} / min
              </p>
              <p className="text-xs text-(--text-dim)">
                Activity source: access logs from published apps.
              </p>
              <h3 className="mt-3 text-sm">Troubleshooting</h3><Disclosure title="Service details" indicator={proxy.nginx_pid === undefined || !proxy.nginx_last_start ? "Some details unknown" : undefined}>
                <p>Software: Nginx</p>
                <p>Process ID: {proxy?.nginx_pid ?? "Unknown"}</p>
                <p>Last start: {proxy?.nginx_last_start || "n/a"}</p>
              </Disclosure>
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
    </Shell>
  );
}
