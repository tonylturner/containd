"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import type { IDSRule } from "../../lib/api";
import { isRuleEnabled } from "./ids-shared";

export function EditRuleModal({ rule, text, setText, onClose, onSave, mutationDisabled, busy, saveError, notice }: {
  rule: IDSRule;
  text: string;
  setText: (value: string) => void;
  onClose: () => void;
  onSave: (rule: IDSRule) => Promise<void>;
  mutationDisabled: boolean;
  busy: boolean;
  saveError: string | null;
  notice: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [advanced, setAdvanced] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { dialog.current?.showModal(); }, []);

  let parsed: IDSRule | null = null;
  try {
    const value = JSON.parse(text);
    if (value && typeof value === "object" && !Array.isArray(value)) parsed = value;
  } catch { /* Invalid advanced input remains editable. */ }
  function update(patch: Partial<IDSRule>) {
    if (parsed) setText(JSON.stringify({ ...parsed, ...patch }, null, 2));
  }
  const condition = parsed?.when ?? {};
  const complex = !!(condition.all || condition.any || condition.not || (condition.value !== null && typeof condition.value === "object"));
  function stringField(key: keyof IDSRule, label: string) {
    return <label key={key} className="min-w-0 text-xs">{label}
      <input className="input-industrial mt-1 w-full" value={String(parsed?.[key] ?? "")} onChange={e => update({ [key]: e.target.value })} />
    </label>;
  }
  async function save() {
    setError(null);
    if (!parsed || typeof parsed.id !== "string" || !parsed.id.trim()) {
      setError("Enter a JSON rule object with a non-empty string ID.");
      return;
    }
    await onSave(parsed);
  }
  return (
    <dialog ref={dialog} aria-labelledby="ids-edit-title" onCancel={e => { e.preventDefault(); if (!busy) onClose(); }}
      className="m-auto max-h-[90dvh] w-[calc(100%-2rem)] max-w-3xl overflow-y-auto rounded-xs border bg-(--surface) p-5 text-(--text) shadow-card-lg backdrop:bg-black/60">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 id="ids-edit-title" className="text-lg font-semibold">Edit: {rule.id}</h2>
        <button disabled={busy} onClick={onClose} className="rounded-xs border px-2 py-1 text-xs">Close</button>
      </div>
      <p className="mb-3 text-xs text-(--text-muted)">Save rule stages this rule and all current IDS page edits. No additional Save is needed; review and commit to apply.</p>
      {notice}
      {(error || saveError) && <p role="alert" className="mb-3 break-words text-sm text-red-400">{error || saveError}</p>}
      <button type="button" aria-expanded={advanced} onClick={() => setAdvanced(!advanced)} className="mb-3 rounded-xs border px-3 py-2 text-sm">Edit JSON</button>
      <fieldset disabled={mutationDisabled} className="min-w-0">
        {advanced ? <label className="block text-xs">Rule JSON
          <textarea value={text} onChange={e => setText(e.target.value)} rows={16} className="input-industrial mt-1 w-full font-mono text-xs" />
        </label> : !parsed ? <p role="alert">Invalid JSON. Use Edit JSON to correct it.</p> : (
          <div className="grid min-w-0 gap-3 md:grid-cols-2">
            {stringField("id", "Rule ID")}
            {stringField("title", "Title")}
            {stringField("description", "Description")}
            {stringField("message", "Message")}
            {stringField("proto", "Protocol")}
            {stringField("kind", "Event kind")}
            <label className="text-xs">Severity
              <select className="input-industrial mt-1 w-full" value={parsed.severity ?? ""} onChange={e => update({ severity: e.target.value })}>
                <option value="">Default (low)</option>
                {["low", "medium", "high", "critical"].map(s => <option key={s}>{s}</option>)}
                {parsed.severity && !["low", "medium", "high", "critical"].includes(parsed.severity) && <option>{parsed.severity}</option>}
              </select>
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={isRuleEnabled(parsed)} onChange={e => update({ enabled: e.target.checked })} />Enabled
            </label>
            {(["srcAddr", "dstAddr", "srcPort", "dstPort"] as const).map((key, i) => stringField(key, ["Source address", "Destination address", "Source port", "Destination port"][i]))}
            <section className="min-w-0 space-y-3 md:col-span-2" aria-label="Match condition">
              <h3 className="text-sm font-semibold">Match condition</h3>
              {complex ? <p className="text-xs">This rule has a compound or list condition. Edit JSON preserves and edits the full condition.</p> : (
                <>
                  <label className="block text-xs">Event field
                    <input className="input-industrial mt-1 w-full" placeholder="attr.function_code" value={condition.field ?? ""}
                      onChange={e => update({ when: { ...condition, field: e.target.value } })} />
                  </label>
                  <label className="block text-xs">Operator
                    <select className="input-industrial mt-1 w-full" value={condition.op ?? ""} onChange={e => update({ when: { ...condition, op: e.target.value } })}>
                      <option value="">Choose operator</option>
                      {["equals", "contains", "regex", "gt", "lt"].map(op => <option key={op}>{op}</option>)}
                      {condition.op && !["equals", "contains", "regex", "gt", "lt"].includes(condition.op) && <option>{condition.op}</option>}
                    </select>
                  </label>
                  <label className="block text-xs">Value type
                    <select className="input-industrial mt-1 w-full" value={typeof condition.value === "number" ? "number" : typeof condition.value === "boolean" ? "boolean" : "string"} onChange={e => update({
                      when: { ...condition, value: e.target.value === "number" ? 0 : e.target.value === "boolean" ? false : "" },
                    })}>
                      <option value="string">Text</option><option value="number">Number</option><option value="boolean">Boolean</option>
                    </select>
                  </label>
                  <label className="block text-xs">Match value
                    {typeof condition.value === "boolean" ? <select className="input-industrial mt-1 w-full" value={String(condition.value)} onChange={e => update({ when: { ...condition, value: e.target.value === "true" } })}>
                      <option value="true">true</option><option value="false">false</option>
                    </select> : <input className="input-industrial mt-1 w-full" type={typeof condition.value === "number" ? "number" : "text"} step="any" value={String(condition.value ?? "")}
                      onChange={e => update({ when: { ...condition, value: typeof condition.value === "number" ? Number(e.target.value) : e.target.value } })} />}
                  </label>
                </>
              )}
            </section>
            <p className="text-xs text-(--text-muted) md:col-span-2">Edit JSON also exposes labels, content matches, YARA strings, references and arbitrary conditions. Unedited fields are preserved.</p>
          </div>
        )}
      </fieldset>
      <div className="mt-4 flex justify-end gap-2">
        <button disabled={busy} onClick={onClose} className="rounded-xs border px-3 py-2 text-sm">Cancel</button>
        <button disabled={mutationDisabled} onClick={() => void save()} className="rounded-xs bg-(--amber) px-3 py-2 text-sm text-white disabled:opacity-50">Save rule</button>
      </div>
    </dialog>
  );
}
