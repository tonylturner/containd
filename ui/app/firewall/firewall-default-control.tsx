"use client";

import { useEffect, useState } from "react";
import { api, type ConfigBundle } from "../../lib/api";
import { isRevisionConflict, isRevisionRequired, revisionError, useConfigEditor } from "../../lib/use-config-editor";
import { ConfirmDialog } from "../../components/ConfirmDialog";

/** The candidate replacement API is the narrowest write for defaultAction. */
export function FirewallDefaultControl({ revision, available, onSaved }: {
  revision: string; available: boolean; onSaved: () => void;
}) {
  const [opened, setOpened] = useState<{ revision: string } | null>(null);
  return <>
    <button disabled={!available} onClick={() => setOpened({ revision })}
      className="rounded-xs border bg-(--surface2) px-2 py-1 text-xs disabled:opacity-50">Change default</button>
    {opened && <DefaultDialog revision={opened.revision} onClose={() => setOpened(null)} onSaved={onSaved} />}
  </>;
}

function DefaultDialog({ revision, onClose, onSaved }: {
  revision: string; onClose: () => void; onSaved: () => void;
}) {
  const draft = useConfigEditor({} as ConfigBundle, false);
  const { readConfig } = draft;
  const [action, setAction] = useState<"ALLOW" | "DENY" | "">("");
  const [ready, setReady] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    void api.getCandidateConfig().then(snapshot => {
      if (!active) return;
      if (!snapshot || snapshot.revision !== revision || !snapshot.data.firewall) {
        setError("Candidate unavailable or changed. Cancel, Refresh and review before changing the default.");
        return;
      }
      readConfig(snapshot, false);
      setAction(snapshot.data.firewall.defaultAction ?? "");
      setReady(true);
    });
    return () => { active = false; };
  }, [revision, readConfig]);

  async function save() {
    if (!ready || saving || !draft.writable) return;
    setSaving(true);
    setError(null);
    const result = await draft.writeRefresh((base, config) => api.setCandidateConfig(base, {
      ...config, firewall: { ...config.firewall, defaultAction: action },
    }), api.getCandidateConfig);
    setSaving(false);
    if (!result.ok) {
      if (isRevisionConflict(result) || isRevisionRequired(result)) {
        // A full-document replacement must never rebase a stale copy.
        setReady(false);
        setError("Configuration changed since you loaded it. Your choice is kept here; Cancel, Refresh and review the latest candidate before saving.");
      } else setError(revisionError(result));
      return;
    }
    if (!result.adopted) { setError("Save acknowledgement unavailable. Reload and review the candidate before making more changes."); return; }
    onSaved();
    onClose();
  }

  return <ConfirmDialog open title="Change default" confirmLabel={!ready ? "Close" : saving ? "Staging..." : "Stage default"}
    variant={action === "ALLOW" ? "danger" : "warning"} onCancel={onClose} onConfirm={() => { if (ready) void save(); else onClose(); }}
    message={<div className="space-y-3">
      <p>Applies to traffic no enforcing rule decides. This stages a candidate change only; review the diff and use Commit-confirmed to apply safely.</p>
      <label className="block">Default action
        <select className="input-industrial mt-1 w-full" value={action} disabled={!ready || saving}
          onChange={event => setAction(event.target.value as "ALLOW" | "DENY" | "")}>
          <option value="">System default (DENY)</option>
          <option value="DENY">DENY</option><option value="ALLOW">ALLOW</option>
        </select>
      </label>
      {action === "ALLOW"
        ? <p role="alert" className="font-semibold text-red-400">Warning: ALLOW permits all unmatched traffic. This can expose networks and devices that have no explicit allow rule.</p>
        : <p>DENY drops unmatched traffic and may interrupt connections without an explicit allow rule. Management access remains reserved.</p>}
      {!ready && !error && <p>Loading candidate...</p>}
      {error && <p role="alert" className="text-red-400">{error}</p>}
    </div>} />;
}
