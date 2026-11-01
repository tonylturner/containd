"use client";

import { useAsyncRefresh } from "../../../../hooks/useAsyncRefresh";

import { useConfigForm } from "../../../../lib/use-config-form";
import { useConfigLoad, useConfigEditor, ConfigEditNotice } from "../../../../lib/use-config-editor";

import { useConfigRefresh } from "../../../../lib/use-config-refresh";

import { useCallback, useEffect, useMemo, useState } from "react";

import { api, isAdmin, type SyslogConfig, type SyslogForwarder, type SyslogStatus } from "../../../../lib/api";
import { Shell } from "../../../../components/Shell";
import { useToast } from "../../../../components/ToastProvider";
import { SaveStateLine } from "../../../../components/SaveStateLine";
import { useSaveAction } from "../../../../hooks/useSaveAction";
import { Skeleton } from "../../../../components/Skeleton";
import { Sparkline } from "../../../../components/Sparkline";
import { Card } from "../../../../components/Card";
import { SyslogEventStatusPanel } from "./syslog-event-status";
import { SyslogAuditStatusPanel } from "./syslog-audit-status";

export default function SyslogPage() {
  const canEdit = isAdmin();
  const { canSave, loadError, checkLoaded } = useConfigLoad();
  const toast = useToast();
  const { editor, cfg, setCfg, adoptConfig, beginSave, failSave, acceptConfig } = useConfigEditor<SyslogConfig>({ forwarders: [], batchSize: 500, flushEvery: 2 }, false);
  const [status, setStatus] = useState<SyslogStatus | null>(null);
  const form = useConfigForm({ forwarder: {
    address: "",
    port: 514,
    proto: "udp",
  } as SyslogForwarder });
  const [newFwd, setNewFwd] = form.field("forwarder");
  const { refreshForm } = form;
  const save = useSaveAction();
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { loading, refresh } = useAsyncRefresh(useCallback(async ({ keepEdits = true }: { keepEdits?: boolean } = {}) => {
    try {
      const svc = await api.getServicesStatus();
      setError(null);
      setStatus(svc?.syslog ?? null);
      const s = await api.getSyslog();
      if (!checkLoaded(s)) return;
      refreshForm(s, keepEdits);
      adoptConfig(s, keepEdits);
      toast("Syslog status refreshed", "success");
      setLastUpdated(new Date());
    } catch (e) {
      checkLoaded(null);
      const msg = e instanceof Error ? e.message : "Failed to refresh syslog.";
      setError(msg);
      toast("Failed to refresh syslog", "error");
    }
  }, [checkLoaded, toast, adoptConfig, refreshForm]));

  useConfigRefresh(refresh);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = window.setInterval(() => {
      void refresh();
    }, 15_000);
    return () => window.clearInterval(t);
  }, [autoRefresh, refresh]);

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
      ...c,
      forwarders: [...(c.forwarders ?? []), { ...newFwd, address: newFwd.address.trim() }],
    }));
    setNewFwd({ address: "", port: 514, proto: "udp" });
  }

  function deleteForwarder(idx: number) {
    if (!canEdit) return;
    setCfg((c) => ({
      ...c,
      forwarders: (c.forwarders ?? []).filter((_, i) => i !== idx),
    }));
  }

  async function onSave() {
    if (!canEdit || !canSave || loading) return;
    setError(null);
    const submitted = beginSave();
    const saved = await save.run("save", () => api.setSyslog(cfg), {
      success: "Syslog staged — commit to apply.",
      failure: "Failed to save syslog settings.",
    });
    if (!saved) { failSave(submitted); return; }
    if (saved.ok) acceptConfig(submitted, saved.data);
    else { failSave(submitted); setError(saved.error); }
  }

  return (
    <Shell
      title="Syslog"
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
              disabled={!canSave || loading || save.pending !== null}
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
      {loadError && <p role="alert" className="mb-4 text-sm text-red-400">{loadError}</p>}
      <ConfigEditNotice superseded={editor.superseded || form.editor.superseded} />
      <fieldset disabled={!canSave} className="min-w-0">
      {!canEdit && (
        <div className="mb-4 rounded-xs border bg-(--surface) px-4 py-3 text-sm text-(--text)">
          View-only mode: configuration changes are disabled.
        </div>
      )}
      {!loading && error && (
        <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      <p className="mb-4 text-xs text-(--text-muted)">
        Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : "\u2014"} {autoRefresh ? "(auto)" : ""}
      </p>
      {status && (
        <div className="mb-4 grid gap-2 rounded-xs border bg-(--surface) p-3 text-xs text-(--text) md:grid-cols-4">
          <div>Forwarders: {status?.configured_forwarders ?? 0}</div>
          <div>Sent: {status?.sent_total ?? 0}</div>
          <div>Failed: {status?.failed_total ?? 0}</div>
          <div>Last flush: {status?.last_flush || "\u2014"}</div>
          <div>Last batch: {status?.last_batch ?? 0}</div>
          <div>Batch limit: {status?.batch_limit ?? 0}</div>
          <div>Hit limit: {status?.hit_limit ? "yes" : "no"}</div>
          <div>Flush interval: {status?.flush_interval_sec ?? cfg.flushEvery ?? 0}s</div>
          {status?.last_error ? (
            <div className="md:col-span-4">Last error: {status.last_error}</div>
          ) : null}
        </div>
      )}
      <SyslogEventStatusPanel events={status?.events} />
      {status?.audit && <SyslogAuditStatusPanel audit={status.audit} />}

      <Card>
        <h2 className="text-lg font-semibold text-(--text)">Forwarders</h2>
        <p className="mt-1 text-sm text-(--text)">
          Send unified events to external syslog collectors.
        </p>
        <p className="mt-2 text-xs text-(--text-muted)">
          Active forwarders: {status?.configured_forwarders ?? 0}
        </p>
        <div className="mt-2 grid gap-3 text-xs text-(--text-muted) md:grid-cols-3">
          <div>
            Log format:
            <select
              value={cfg.format ?? "rfc5424"}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  format: e.target.value as SyslogConfig["format"],
                }))
              }
              className="ml-2 input-industrial"
            >
              <option value="rfc5424">RFC5424</option>
              <option value="json">JSON</option>
            </select>
          </div>
          <div>
            Batch size:
            <input
              type="number"
              min={1}
              max={5000}
              value={cfg.batchSize ?? 500}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  batchSize: Number(e.target.value),
                }))
              }
              className="ml-2 w-24 input-industrial"
            />
          </div>
          <div>
            Flush every (s):
            <input
              type="number"
              min={1}
              max={60}
              value={cfg.flushEvery ?? 2}
              disabled={!canEdit}
              onChange={(e) =>
                setCfg((c) => ({
                  ...c,
                  flushEvery: Number(e.target.value),
                }))
              }
              className="ml-2 w-24 input-industrial"
            />
          </div>
        </div>

        <div className="mt-3">
          {loading ? (
            <div className="space-y-2">
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-full" />
            </div>
          ) : status?.sparkline.length ? (
            <Sparkline
              values={status.sparkline}
              color="var(--primary)"
              background="linear-gradient(180deg, rgba(37,99,235,0.08), rgba(6,182,212,0.04))"
              title="Syslog events per minute"
            />
          ) : null}
          {!loading && typeof status?.rate_per_min === "number" ? (
            <p className="mt-2 text-xs text-(--text-muted)">
              Rate: {status?.rate_per_min.toFixed(1)} / min
            </p>
          ) : null}
          {!loading && typeof status?.errors_rate_per_min === "number" ? (
            <p className="mt-1 text-xs">
              Errors: {status?.errors_rate_per_min.toFixed(1)} / min
            </p>
          ) : null}
        </div>

        <div className="mt-4 grid gap-2 md:grid-cols-4">
          <input
            value={newFwd.address}
            onChange={(e) => setNewFwd((f) => ({ ...f, address: e.target.value }))}
            disabled={!canEdit}
            placeholder="address"
            className="input-industrial"
          />
          <input
            type="number"
            value={newFwd.port}
            onChange={(e) => setNewFwd((f) => ({ ...f, port: Number(e.target.value) }))}
            disabled={!canEdit}
            placeholder="port"
            className="input-industrial"
          />
          <select
            value={newFwd.proto ?? "udp"}
            onChange={(e) => setNewFwd((f) => ({ ...f, proto: e.target.value as "udp" | "tcp" }))}
            disabled={!canEdit}
            className="input-industrial"
          >
            <option value="udp">UDP</option>
            <option value="tcp">TCP</option>
          </select>
          {canEdit && (
            <button
              onClick={addForwarder}
              className="rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Add
            </button>
          )}
        </div>

        <div className="mt-4 overflow-hidden rounded-xs border bg-(--surface)">
          <table className="w-full text-sm">
            <thead className="bg-black/40 text-left text-xs uppercase tracking-wide text-(--text)">
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
                  <td className="px-4 py-4 text-(--text-muted)" colSpan={4}>
                    No forwarders configured.
                  </td>
                </tr>
              )}
              {(cfg.forwarders ?? []).map((f, i) => (
                <tr key={`${f.address}-${i}`} className="border-t table-row-hover transition-ui">
                  <td className="px-4 py-3 text-(--text)">{f.address}</td>
                  <td className="px-4 py-3 text-(--text)">{f.port}</td>
                  <td className="px-4 py-3 text-(--text)">{f.proto ?? "udp"}</td>
                  <td className="px-4 py-3 text-right">
                    {canEdit && (
                      <button
                        onClick={() => deleteForwarder(i)}
                        className="rounded-md px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
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

        <SaveStateLine state={save.state} saved="staged — commit to apply." />
      </Card>
      </fieldset>
    </Shell>
  );
}
