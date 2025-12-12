 "use client";

import { useEffect, useMemo, useState } from "react";

import {
  fetchDataPlane,
  setDataPlane,
  type DataPlaneConfig,
} from "../../lib/api";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function DataPlanePage() {
  const [config, setConfig] = useState<DataPlaneConfig>({
    captureInterfaces: [],
    enforcement: false,
    enforceTable: "containd",
    dpiMock: false,
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");

  useEffect(() => {
    fetchDataPlane().then((dp) => {
      if (dp) {
        setConfig({
          captureInterfaces: dp.captureInterfaces ?? [],
          enforcement: dp.enforcement ?? false,
          enforceTable: dp.enforceTable ?? "containd",
          dpiMock: dp.dpiMock ?? false,
        });
      }
    });
  }, []);

  const ifaceCSV = useMemo(
    () => (config.captureInterfaces ?? []).join(", "),
    [config.captureInterfaces],
  );

  async function onSave() {
    setSaveState("saving");
    const saved = await setDataPlane(config);
    setSaveState(saved ? "saved" : "error");
    setTimeout(() => setSaveState("idle"), 1500);
  }

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 opacity-30">
        <div className="grid-overlay h-full w-full" />
      </div>
      <main className="relative mx-auto max-w-3xl px-6 py-16">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-white">Dataplane Settings</h1>
          <a
            href="/"
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/10"
          >
            Back
          </a>
        </div>

        <div className="mt-8 space-y-6 rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Enforcement</h2>
              <p className="text-sm text-slate-300">
                Apply compiled rules to nftables on the engine.
              </p>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={config.enforcement ?? false}
                onChange={(e) =>
                  setConfig((c) => ({ ...c, enforcement: e.target.checked }))
                }
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Enabled
            </label>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-200">
              nftables table name
            </label>
            <input
              type="text"
              value={config.enforceTable ?? ""}
              onChange={(e) =>
                setConfig((c) => ({ ...c, enforceTable: e.target.value }))
              }
              placeholder="containd"
              className="mt-2 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-200">
              Capture interfaces
            </label>
            <p className="mt-1 text-xs text-slate-400">
              Comma-separated Linux interface names to inspect (empty disables
              capture).
            </p>
            <input
              type="text"
              value={ifaceCSV}
              onChange={(e) =>
                setConfig((c) => ({
                  ...c,
                  captureInterfaces: e.target.value
                    .split(",")
                    .map((s) => s.trim())
                    .filter(Boolean),
                }))
              }
              placeholder="eth0, eth1"
              className="mt-2 w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
            />
          </div>

          <div className="flex items-center justify-between rounded-xl border border-white/10 bg-black/30 p-4">
            <div>
              <h3 className="text-sm font-semibold text-white">DPI mock loop</h3>
              <p className="text-xs text-slate-400">
                Lab-only: emit synthetic Modbus events for visibility.
              </p>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={config.dpiMock ?? false}
                onChange={(e) =>
                  setConfig((c) => ({ ...c, dpiMock: e.target.checked }))
                }
                className="h-4 w-4 rounded border-white/20 bg-black/30"
              />
              Enabled
            </label>
          </div>

          <div className="flex items-center justify-end gap-3">
            {saveState === "error" && (
              <span className="text-sm text-amber">Save failed</span>
            )}
            {saveState === "saved" && (
              <span className="text-sm text-mint">Saved</span>
            )}
            <button
              onClick={onSave}
              disabled={saveState === "saving"}
              className="rounded-lg bg-mint/20 px-4 py-2 text-sm font-semibold text-mint hover:bg-mint/30 disabled:opacity-50"
            >
              {saveState === "saving" ? "Saving..." : "Save"}
            </button>
          </div>
        </div>
      </main>
    </div>
  );
}

