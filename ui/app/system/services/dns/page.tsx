"use client";

import { useEffect, useMemo, useState } from "react";

import { api, type DNSConfig } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function DNSPage() {
  const [cfg, setCfg] = useState<DNSConfig>({
    enabled: false,
    listenPort: 53,
    upstreamServers: [],
    cacheSizeMB: 0,
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const s = await api.getDNS();
    setCfg({
      enabled: s?.enabled ?? false,
      listenPort: s?.listenPort ?? 53,
      listenZones: s?.listenZones ?? [],
      upstreamServers: s?.upstreamServers ?? [],
      cacheSizeMB: s?.cacheSizeMB ?? 0,
    });
  }

  useEffect(() => {
    refresh();
  }, []);

  const upstreamText = useMemo(
    () => (cfg.upstreamServers ?? []).join("\n"),
    [cfg.upstreamServers],
  );

  async function onSave() {
    setError(null);
    setSaveState("saving");
    const saved = await api.setDNS(cfg);
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save DNS settings.");
    setTimeout(() => setSaveState("idle"), 1500);
    if (saved) setCfg(saved);
  }

  return (
    <Shell
      title="DNS"
      actions={
        <div className="flex items-center gap-2">
          <button
            onClick={refresh}
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Refresh
          </button>
          <button
            onClick={onSave}
            className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
          >
            Save
          </button>
        </div>
      }
    >
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
        <h2 className="text-lg font-semibold text-white">Resolver</h2>
        <p className="mt-1 text-sm text-slate-300">
          Configure the embedded Unbound DNS resolver.
        </p>

        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <label className="flex items-center gap-2 text-sm text-slate-200">
            <input
              type="checkbox"
              checked={cfg.enabled ?? false}
              onChange={(e) =>
                setCfg((c) => ({ ...c, enabled: e.target.checked }))
              }
              className="h-4 w-4"
            />
            Enable DNS resolver
          </label>

          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">
              Listen Port
            </label>
            <input
              type="number"
              value={cfg.listenPort ?? 53}
              onChange={(e) =>
                setCfg((c) => ({ ...c, listenPort: Number(e.target.value) }))
              }
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div>
            <label className="text-xs uppercase tracking-wide text-slate-400">
              Cache Size (MB)
            </label>
            <input
              type="number"
              value={cfg.cacheSizeMB ?? 0}
              onChange={(e) =>
                setCfg((c) => ({ ...c, cacheSizeMB: Number(e.target.value) }))
              }
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
          </div>

          <div className="md:col-span-2">
            <label className="text-xs uppercase tracking-wide text-slate-400">
              Upstream Servers (one per line)
            </label>
            <textarea
              rows={5}
              value={upstreamText}
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
              className="mt-1 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <p className="mt-1 text-xs text-slate-400">
              Leave empty to use root hints (recursive mode).
            </p>
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
