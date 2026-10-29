"use client";

import { useCallback, useState, type SetStateAction } from "react";
import { accept, adopt, fresh, isDirty, sameConfig, type ConfigEditor } from "./config-editor";

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
  const acceptConfig = useCallback((submitted: ConfigEditor<T>, next: T) => {
    setEditor((e) => accept(e, submitted, next));
  }, []);
  const setText = useCallback((key: string, value: string) => {
    setEditor((e) => ({ ...e, raw: { ...e.raw, [key]: value } }));
  }, []);
  const clearText = useCallback((prefix: string) => {
    setEditor((e) => ({ ...e, raw: Object.fromEntries(Object.entries(e.raw).filter(([key]) => !key.startsWith(prefix))) }));
  }, []);
  // Row saves acknowledge only that row. Other drafts, and typing after the
  // request started, are not part of the acknowledgement.
  const acceptRow = useCallback((submitted: ConfigEditor<T>, update: (rows: T) => T, prefix: string) => {
    setEditor((e) => {
      const raw = Object.fromEntries(Object.entries(e.raw).filter(([key, value]) =>
        !key.startsWith(prefix) || value !== submitted.raw[key]));
      const server = update(e.server);
      const pending = Object.keys(raw).length > 0;
      return { cfg: pending ? update(e.cfg) : server, server, raw, superseded: pending && e.superseded };
    });
  }, []);
  function field<V>(key: string, derived: V): [V, (value: SetStateAction<V>) => void] {
    const value = key in editor.raw ? JSON.parse(editor.raw[key]) as V : derived;
    return [value, (update) => setEditor((e) => {
      const current = key in e.raw ? JSON.parse(e.raw[key]) as V : derived;
      const next = typeof update === "function" ? (update as (v: V) => V)(current) : update;
      if (sameConfig(next, derived)) {
        const raw = { ...e.raw };
        delete raw[key];
        return { ...e, raw };
      }
      return { ...e, raw: { ...e.raw, [key]: JSON.stringify(next) } };
    })];
  }
  return {
    editor, cfg: editor.cfg, setCfg, adoptConfig, acceptConfig,
    dirty: isDirty(editor), setText, field, clearText, acceptRow,
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
