"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type NTPConfig } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function NTPPage() {
  const canEdit = isAdmin();
  const [cfg, setCfg] = useState<NTPConfig>({
    enabled: false,
    servers: [],
    intervalSeconds: 0,
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const s = await api.getNTP();
    setCfg({
      enabled: s?.enabled ?? false,
      servers: s?.servers ?? [],
      intervalSeconds: s?.intervalSeconds ?? 0,
    });
  }

  useEffect(() => {
    refresh();
  }, []);

  const serversText = useMemo(
    () => (cfg.servers ?? []).join("\n"),
    [cfg.servers],
  );

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setNTP(cfg);
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save NTP settings.");
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
