"use client";

import { useEffect, useEffectEvent, useState } from "react";
import { revisionError } from "../../lib/config-revision";
import { api } from "../../lib/api";
import { useConfigView } from "../../lib/use-config-revision";

/** An upload owns its destination base until acknowledgement or explicit
 * discard. Background diff refreshes never rebase the selected file. */
export function IDSRestore({ revision, onStatus, onChanged }: {
  revision?: string;
  onStatus: (status: string) => void;
  onChanged: () => unknown;
}) {
  const draft = useConfigView<unknown>(null);
  const { readConfig } = draft;
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const receiveRevision = useEffectEvent((revision: string) => readConfig({ data: null, revision }, true, !!file));
  useEffect(() => {
    if (revision) receiveRevision(revision);
  }, [revision]);

  async function restore(selected: File) {
    if (busy || !revision || !draft.writable) return;
    setBusy(true);
    onStatus("");
    try {
      const result = await draft.writeRefresh(async base => {
        const rules = JSON.parse(await selected.text());
        if (!Array.isArray(rules)) throw new Error("Invalid IDS rules file (expected JSON array).");
        return api.restoreIDSRules(base, rules);
      }, api.diffConfig);
      if (result.ok) onStatus(`IDS restore staged (${result.data.count} rules) — commit to apply.`);
      else if (revisionError(result) !== null) onStatus(`Restore failed: ${result.error}`);
      if (result.ok && result.adopted) setFile(current => current === selected ? null : current);
      void onChanged();
    } catch {
      onStatus("Invalid JSON file.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-w-0">
      {draft.revisionNotice(async () => {
        const snapshot = await api.diffConfig();
        if (!snapshot) { onStatus("Unable to reload the restore destination. Your file is kept."); return; }
        readConfig(snapshot, false);
        setFile(null);
        void onChanged();
      })}
      <div className="flex flex-wrap items-center gap-2">
        <label className="cursor-pointer rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui">
          Select rule backup
          <input type="file" accept=".json" className="hidden" disabled={busy || !revision || !draft.writable}
            onChange={(event) => {
              const selected = event.target.files?.[0];
              event.target.value = "";
              if (!selected) return;
              setFile(selected);
              void restore(selected);
            }} />
        </label>
        {file && <>
          <span className="break-all text-xs">{file.name}</span>
          <button disabled={busy || !revision || !draft.writable} onClick={() => void restore(file)}
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white transition-ui disabled:opacity-50">
            Stage rule restore
          </button>
        </>}
      </div>
    </div>
  );
}
