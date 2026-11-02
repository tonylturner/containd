"use client";

import { useEffect, useState } from "react";
import type { ApiResult, DataPlaneConfig } from "../../lib/api";
import type { ConfigBase } from "../../lib/config-boundary";
import { ConfigEditNotice, revisionError, useConfigEditor } from "../../lib/use-config-editor";
import { Disclosure } from "../../components/Disclosure";

function fields(config: DataPlaneConfig) {
  return { queue: String(config.nfqueueGroup || 101), log: String(config.nflogGroup ?? 0), context: config };
}

export function InlineInspectionSetup({ config, revision, available, onSave }: {
  config: DataPlaneConfig; revision: string; available: boolean;
  onSave: (base: ConfigBase, config: DataPlaneConfig) => Promise<ApiResult<DataPlaneConfig> | null>;
}) {
  const draft = useConfigEditor(() => fields(config), available, revision);
  const { cfg, setCfg, readConfig } = draft;
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<{ warning?: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const conflict = !!draft.editor.conflictRevision;
  useEffect(() => { readConfig({ data: fields(config), revision }, true); }, [config, revision, readConfig]);

  async function stage() {
    if (!available || saving || conflict) return;
    const queue = Number(cfg.queue);
    const log = Number(cfg.log);
    if (!/^\d+$/.test(cfg.queue) || !Number.isInteger(queue) || queue < 1 || queue > 65535 ||
      !/^\d+$/.test(cfg.log) || !Number.isInteger(log) || log < 0 || log > 65535) {
      setError("Inline queue must be 1–65535; logging group must be 0–65535 (0 disables packet logging).");
      return;
    }
    setError(null);
    setSaved(null);
    setSaving(true);
    const result = await draft.write((base, submitted) => onSave(base, {
      ...submitted.context, nfqueueGroup: queue, nflogGroup: log,
    }), { replace: data => fields(data) });
    setSaving(false);
    if (!result.ok) { setError(revisionError(result)); return; }
    if (result.adopted) setSaved({ warning: result.warning });
  }

  return <section id="inline-inspection" aria-label="Inline inspection" className="scroll-mt-4 rounded-xs border bg-(--surface2) p-3">
    <h3 className="text-sm font-semibold">Inline inspection</h3>
    <p className="mt-1 text-xs text-(--text-muted)">
      Capture interfaces observe copies and cannot block commands. ICS Enforce requires an inline queue.
      Monitor remains non-blocking. Inline setup alone does not enable DPI or firewall enforcement;
      review those settings and coverage before applying.
    </p>
    <p className="mt-2 text-xs">{!available ? "Inline inspection status unknown" : config.nfqueueGroup ? "Inline inspection configured in candidate" : "Monitor only — inline inspection is not configured"}</p>
    {conflict ? <div role="alert" className="mt-2 text-xs text-(--amber)">
      <p>Configuration changed since you loaded it. Your queue settings are kept here; Reload and review before saving.
        The complete dataplane document cannot be safely rebased over another operator&apos;s changes.</p>
      <button type="button" onClick={() => window.location.reload()} className="mt-2 rounded-xs border px-2 py-1">Reload</button>
    </div> : <ConfigEditNotice superseded={draft.editor.superseded} {...draft.conflictProps} onReload={() => window.location.reload()} />}
    <fieldset disabled={!available || saving || conflict} className="mt-3 min-w-0">
      <Disclosure title="Queue and logging settings" defaultOpen indicator={config.nfqueueGroup ? "Configured" : undefined}>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-xs">Inline queue (NFQUEUE)
            <input type="number" min={1} max={65535} value={cfg.queue}
              onChange={event => setCfg(current => ({ ...current, queue: event.target.value }))}
              className="input-industrial mt-1 w-full" />
          </label>
          <label className="text-xs">Packet logging group (NFLOG)
            <input type="number" min={0} max={65535} value={cfg.log}
              onChange={event => setCfg(current => ({ ...current, log: event.target.value }))}
              className="input-industrial mt-1 w-full" />
          </label>
        </div>
        <p className="mt-2 text-xs text-(--text-muted)">Recommended queue: 101; optional logging group: 100. Queue and logging numbers are independent.
          Choose a queue not owned by another local consumer; runtime coverage reports ownership failures.</p>
      </Disclosure>
      <button type="button" onClick={() => void stage()} disabled={!draft.writable}
        className="mt-3 rounded-xs border px-3 py-1.5 text-xs disabled:opacity-50">{saving ? "Staging..." : "Stage inline inspection"}</button>
    </fieldset>
    {error && <p role="alert" className="mt-2 text-xs text-red-400">{error}</p>}
    {saved && <p role="status" className="mt-2 text-xs text-emerald-400">Inline inspection staged — review changes and use Commit-confirmed to apply safely.
      {saved.warning && ` Warning: ${saved.warning}`}</p>}
  </section>;
}
