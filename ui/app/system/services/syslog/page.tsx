"use client";

import { useEffect, useMemo, useState } from "react";

import { api, isAdmin, type SyslogConfig, type SyslogForwarder } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function SyslogPage() {
  const canEdit = isAdmin();
  const [cfg, setCfg] = useState<SyslogConfig>({ forwarders: [] });
  const [newFwd, setNewFwd] = useState<SyslogForwarder>({
    address: "",
    port: 514,
    proto: "udp",
  });
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    const s = await api.getSyslog();
    setCfg(s ?? { forwarders: [] });
  }

  useEffect(() => {
    refresh();
  }, []);

  const fwdCount = useMemo(() => cfg.forwarders?.length ?? 0, [cfg.forwarders]);

  function addForwarder() {
    if (!canEdit) return;
    setError(null);
    if (!newFwd.address.trim()) {
      setError("Address required.");
      return;
    }
    if (!newFwd.port || newFwd.port <= 0 || newFwd.port > 65535) {
      setError("Port must be valid.");
      return;
    }
    setCfg((c) => ({
      forwarders: [...(c.forwarders ?? []), { ...newFwd, address: newFwd.address.trim() }],
    }));
    setNewFwd({ address: "", port: 514, proto: "udp" });
  }

  function deleteForwarder(idx: number) {
    if (!canEdit) return;
    setCfg((c) => ({
      forwarders: (c.forwarders ?? []).filter((_, i) => i !== idx),
    }));
  }

  async function onSave() {
    if (!canEdit) return;
    setError(null);
    setSaveState("saving");
    const saved = await api.setSyslog(cfg);
    setSaveState(saved ? "saved" : "error");
    if (!saved) setError("Failed to save syslog settings.");
    setTimeout(() => setSaveState("idle"), 1500);
    if (saved) setCfg(saved);
  }

  return (
    <Shell
      title="Syslog"
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
        <h2 className="text-lg font-semibold text-white">Forwarders</h2>
        <p className="mt-1 text-sm text-slate-300">
          Send unified events to external syslog collectors.
        </p>

        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <input
            value={newFwd.address}
            onChange={(e) => setNewFwd((f) => ({ ...f, address: e.target.value }))}
            disabled={!canEdit}
            placeholder="address"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <input
            type="number"
            value={newFwd.port}
            onChange={(e) => setNewFwd((f) => ({ ...f, port: Number(e.target.value) }))}
            disabled={!canEdit}
            placeholder="port"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <select
            value={newFwd.proto ?? "udp"}
            onChange={(e) =>
              setNewFwd((f) => ({ ...f, proto: e.target.value as "udp" | "tcp" }))
            }
            disabled={!canEdit}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          >
            <option value="udp">udp</option>
            <option value="tcp">tcp</option>
          </select>
          {canEdit && (
            <button
              onClick={addForwarder}
              className="rounded-lg bg-white/10 px-3 py-2 text-sm text-white hover:bg-white/20"
            >
              Add
            </button>
          )}
        </div>

        <div className="mt-4 overflow-hidden rounded-xl border border-white/10 bg-black/30">
          <table className="w-full text-sm">
            <thead className="bg-black/40 text-left text-xs uppercase tracking-wide text-slate-300">
              <tr>
                <th className="px-4 py-3">Address</th>
                <th className="px-4 py-3">Port</th>
                <th className="px-4 py-3">Proto</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {fwdCount === 0 && (
                <tr>
                  <td className="px-4 py-4 text-slate-400" colSpan={4}>
                    No forwarders configured.
                  </td>
                </tr>
              )}
              {(cfg.forwarders ?? []).map((f, i) => (
                <tr key={`${f.address}-${i}`} className="border-t border-white/5">
                  <td className="px-4 py-3 text-slate-200">{f.address}</td>
                  <td className="px-4 py-3 text-slate-200">{f.port}</td>
                  <td className="px-4 py-3 text-slate-200">{f.proto ?? "udp"}</td>
                  <td className="px-4 py-3 text-right">
                    {canEdit && (
                      <button
                        onClick={() => deleteForwarder(i)}
                        className="rounded-md bg-amber/20 px-2 py-1 text-xs text-amber hover:bg-amber/30"
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
