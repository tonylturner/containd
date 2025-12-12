"use client";

import { useEffect, useMemo, useState } from "react";

import {
  api,
  type ForwardProxyConfig,
  type ReverseProxyConfig,
  type ReverseProxySite,
} from "../../lib/api";
import { Shell } from "../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function ProxiesPage() {
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

  async function refresh() {
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
  }

  useEffect(() => {
    refresh();
  }, []);

  const listenZonesCSV = useMemo(
    () => (forward.listenZones ?? []).join(", "),
    [forward.listenZones],
  );
  const allowedDomainsCSV = useMemo(
    () => (forward.allowedDomains ?? []).join(", "),
    [forward.allowedDomains],
  );

  async function onSaveForward() {
    setError(null);
    setSaveState("saving");
    const saved = await api.setForwardProxy(forward);
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save forward proxy settings.");
    setTimeout(() => setSaveState("idle"), 1500);
  }

  async function onSaveReverse() {
    setError(null);
    setSaveState("saving");
    const saved = await api.setReverseProxy(reverse);
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save reverse proxy settings.");
    setTimeout(() => setSaveState("idle"), 1500);
  }

  function addSite() {
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
    setReverse((r) => ({
      ...r,
      sites: (r.sites ?? []).filter((s) => s.name !== name),
    }));
  }

  return (
    <Shell
      title="Proxies"
      actions={
        <button
          onClick={refresh}
          className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
        >
          Refresh
        </button>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="grid gap-6 md:grid-cols-2">
        <section className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Forward proxy</h2>
          <p className="mt-1 text-sm text-slate-300">
            Explicit forward proxy powered by Envoy. Configure clients and
            domains in future phases; JSON import/export already supports full
            fields.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={forward.enabled ?? false}
                onChange={(e) =>
                  setForward((f) => ({ ...f, enabled: e.target.checked }))
                }
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Enabled
            </label>

            <div>
              <label className="block text-sm font-medium text-slate-200">
                Listen port
              </label>
              <input
                type="number"
                value={forward.listenPort ?? 3128}
                onChange={(e) =>
                  setForward((f) => ({
                    ...f,
                    listenPort: Number(e.target.value),
                  }))
                }
                className="mt-2 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-200">
                Listen zones
              </label>
              <p className="mt-1 text-xs text-slate-400">
                Comma-separated zones where proxy listens.
              </p>
              <input
                type="text"
                value={listenZonesCSV}
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
                className="mt-2 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-200">
                Allowed domains
              </label>
              <p className="mt-1 text-xs text-slate-400">
                Comma-separated FQDN patterns (e.g. *.vendor.com).
              </p>
              <input
                type="text"
                value={allowedDomainsCSV}
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
                className="mt-2 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
              />
            </div>

            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={forward.logRequests ?? false}
                onChange={(e) =>
                  setForward((f) => ({ ...f, logRequests: e.target.checked }))
                }
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Log requests
            </label>

            <div className="flex items-center justify-end gap-3">
              {saveState === "error" && (
                <span className="text-sm text-amber">Save failed</span>
              )}
              {saveState === "saved" && (
                <span className="text-sm text-mint">Saved</span>
              )}
              <button
                onClick={onSaveForward}
                disabled={saveState === "saving"}
                className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
              >
                {saveState === "saving" ? "Saving..." : "Save"}
              </button>
            </div>
          </div>
        </section>

        <section className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Reverse proxy</h2>
          <p className="mt-1 text-sm text-slate-300">
            Published services powered by Nginx. Add sites to expose internal
            apps.
          </p>

          <div className="mt-5 space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={reverse.enabled ?? false}
                onChange={(e) =>
                  setReverse((r) => ({ ...r, enabled: e.target.checked }))
                }
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Enabled
            </label>

            <div className="rounded-xl border border-white/10 bg-black/30 p-4">
              <h3 className="text-sm font-semibold text-white">Add site</h3>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <input
                  type="text"
                  value={newSite.name}
                  onChange={(e) =>
                    setNewSite((s) => ({ ...s, name: e.target.value }))
                  }
                  placeholder="site name"
                  className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
                <input
                  type="number"
                  value={newSite.listenPort}
                  onChange={(e) =>
                    setNewSite((s) => ({
                      ...s,
                      listenPort: Number(e.target.value),
                    }))
                  }
                  placeholder="listen port"
                  className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
                <input
                  type="text"
                  value={(newSite.backends ?? []).join(", ")}
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
                  className="md:col-span-2 rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
                <input
                  type="text"
                  value={(newSite.hostnames ?? []).join(", ")}
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
                  className="md:col-span-2 rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
                />
              </div>
              <div className="mt-3 flex justify-end">
                <button
                  onClick={addSite}
                  className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
                >
                  Add
                </button>
              </div>
            </div>

            <div className="space-y-2">
              {(reverse.sites ?? []).length === 0 && (
                <div className="text-sm text-slate-400">
                  No reverse proxy sites configured.
                </div>
              )}
              {(reverse.sites ?? []).map((site) => (
                <div
                  key={site.name}
                  className="flex items-center justify-between rounded-lg border border-white/10 bg-black/30 px-3 py-2"
                >
                  <div>
                    <div className="text-sm font-semibold text-white">
                      {site.name}
                    </div>
                    <div className="text-xs text-slate-400">
                      port {site.listenPort} → {(site.backends ?? []).join(", ")}
                    </div>
                  </div>
                  <button
                    onClick={() => deleteSite(site.name)}
                    className="rounded-md border border-white/10 bg-white/5 px-2 py-1 text-xs text-slate-200 hover:bg-white/10"
                  >
                    Delete
                  </button>
                </div>
              ))}
            </div>

            <div className="flex items-center justify-end gap-3">
              {saveState === "error" && (
                <span className="text-sm text-amber">Save failed</span>
              )}
              {saveState === "saved" && (
                <span className="text-sm text-mint">Saved</span>
              )}
              <button
                onClick={onSaveReverse}
                disabled={saveState === "saving"}
                className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
              >
                {saveState === "saving" ? "Saving..." : "Save"}
              </button>
            </div>
          </div>
        </section>
      </div>
    </Shell>
  );
}

