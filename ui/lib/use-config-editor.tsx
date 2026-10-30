"use client";

import { useCallback, useState, type SetStateAction } from "react";
import { accept, acceptCollection as acknowledge, adopt, beginSave as begin, failSave as fail, fresh, isDirty, sameConfig, type ConfigSubmission } from "./config-editor";

export function useConfigEditor<T>(initial: T | (() => T)) {
  const [editor, setEditor] = useState(() => fresh(
    typeof initial === "function" ? (initial as () => T)() : initial,
  ));
  const setCfg = useCallback((update: SetStateAction<T>) => {
    setEditor((e) => ({ ...e, cfg: typeof update === "function" ? (update as (cfg: T) => T)(e.cfg) : update }));
  }, []);
  const adoptConfig = useCallback((next: T, keepEdits = true) => {
    setEditor((e) => adopt(e, next, keepEdits));
  }, []);
  // A submission is captured before enqueueing state, never inside an updater
  // (React may replay updaters). Tokens let independent row saves overlap.
  const beginSave = (raw = editor.raw): ConfigSubmission<T> => {
    const submitted = { id: Symbol("config-save"), cfg: editor.cfg, raw };
    setEditor((e) => begin(e, submitted));
    return submitted;
  };
  const failSave = useCallback((submitted: ConfigSubmission<T>) => {
    setEditor((e) => fail(e, submitted));
  }, []);
  const acceptConfig = useCallback((submitted: ConfigSubmission<T>, next: T) => {
    setEditor((e) => accept(e, submitted, next));
  }, []);
  const setText = useCallback((key: string, value: string) => {
    setEditor((e) => ({ ...e, raw: { ...e.raw, [key]: value } }));
  }, []);
  const clearText = useCallback((prefix: string) => {
    setEditor((e) => ({ ...e, raw: Object.fromEntries(Object.entries(e.raw).filter(([key]) => !key.startsWith(prefix))) }));
  }, []);
  const acceptCollection = useCallback((update: (cfg: T) => T, prefixes: string[] = []) => {
    setEditor((e) => acknowledge(e, update, prefixes));
  }, []);
  // Row saves acknowledge only that row. Other drafts, and typing after the
  // request started, are not part of the acknowledgement.
  const acceptRow = useCallback((submitted: ConfigSubmission<T>, update: (rows: T) => T, prefix: string) => {
    setEditor((e) => acknowledge(e, update, [prefix], submitted));
  }, []);
  function field<V>(key: string, derived: V): [V, (value: SetStateAction<V>) => void] {
    const value = key in editor.raw ? JSON.parse(editor.raw[key]) as V : derived;
    return [value, (update) => setEditor((e) => {
      const current = key in e.raw ? JSON.parse(e.raw[key]) as V : derived;
      const next = typeof update === "function" ? (update as (v: V) => V)(current) : update;
      // Reverting to a pre-save value is still a new edit while saving.
      if (sameConfig(next, derived) && e.pending.length === 0) {
        const raw = { ...e.raw };
        delete raw[key];
        return { ...e, raw };
      }
      return { ...e, raw: { ...e.raw, [key]: JSON.stringify(next) } };
    })];
  }
  return {
    editor, cfg: editor.cfg, setCfg, adoptConfig, beginSave, failSave, acceptConfig,
    dirty: isDirty(editor), setText, field, clearText, acceptRow, acceptCollection,
    text: (key: string, derived: string) => editor.raw[key] ?? derived,
  };
}

export function ConfigEditNotice({ superseded }: { superseded: boolean }) {
  return superseded ? (
    <p role="status" aria-label="Unsaved edits" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
      Unsaved edits kept: settings changed on the server while you were editing. Review before saving; Refresh discards your edits.
    </p>
  ) : null;
}

export type ConfigFields = Pick<ReturnType<typeof useConfigEditor<unknown>>, "field" | "clearText">;
