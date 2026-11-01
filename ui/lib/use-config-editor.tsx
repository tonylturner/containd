"use client";

import { useCallback, useLayoutEffect, useRef, useState, type SetStateAction } from "react";
import { accept, acceptCollection as acknowledge, adopt, beginSave as begin, failSave as fail, fresh, isDirty, keepEdits, sameConfig, type ConfigSubmission } from "./config-editor";
import { revisionFailure } from "./config-revision";
import type { ApiFailure } from "./api";

export { isRevisionConflict, isRevisionRequired } from "./config-revision";

/** A missing authoritative read never authorizes a write or resets a draft.
 * Keep availability separate from save errors and editable form defaults.
 */
export function useConfigLoad() {
  const availableRef = useRef(false);
  const [canSave, setCanSave] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const checkLoaded = useCallback(<T,>(value: T | null | undefined): value is T => {
    const available = value != null;
    availableRef.current = available;
    setCanSave(available);
    setLoadError(available ? null : "Configuration unavailable. Refresh successfully before saving.");
    return available;
  }, []);
  // Confirmation dialogs can retain a callback from before a failed refresh.
  const canSaveNow = useCallback(() => availableRef.current, []);
  return { canSave, canSaveNow, loadError, checkLoaded };
}

export function useConfigEditor<T>(initial: T | (() => T), initialLoaded = true, revision?: string) {
  const authoritative = useRef(initialLoaded);
  const [editor, setEditor] = useState(() => fresh(
    typeof initial === "function" ? (initial as () => T)() : initial, revision,
  ));
  const latest = useRef(editor);
  useLayoutEffect(() => { latest.current = editor; }, [editor]);
  const getBaseRevision = useCallback(() => latest.current.baseRevision, []);
  const setCfg = useCallback((update: SetStateAction<T>) => {
    setEditor((e) => ({ ...e, cfg: typeof update === "function" ? (update as (cfg: T) => T)(e.cfg) : update }));
  }, []);
  const adoptConfig = useCallback((next: T, keepEdits = true, revision?: string) => {
    // Stand-in defaults cannot become a dirty draft's authoritative base.
    const keep = keepEdits && authoritative.current;
    authoritative.current = true;
    setEditor((e) => adopt(e, next, keep, revision));
  }, []);
  // A submission is captured before enqueueing state, never inside an updater
  // (React may replay updaters). Tokens let independent row saves overlap.
  const beginSave = (raw = editor.raw): ConfigSubmission<T> => {
    const submitted = { id: Symbol("config-save"), cfg: editor.cfg, raw, baseRevision: editor.baseRevision };
    setEditor((e) => begin(e, submitted));
    return submitted;
  };
  const failSave = useCallback((submitted: ConfigSubmission<T>, failure?: ApiFailure) => {
    setEditor((e) => !e.pending.some(entry => entry.id === submitted.id) ? e :
      failure ? revisionFailure(fail(e, submitted), failure) : fail(e, submitted));
  }, []);
  const reportFailure = useCallback((failure: ApiFailure) => {
    setEditor((e) => revisionFailure(e, failure));
  }, []);
  const acceptConfig = useCallback((submitted: ConfigSubmission<T>, next: T, revision?: string) => {
    setEditor((e) => accept(e, submitted, next, revision));
  }, []);
  const setText = useCallback((key: string, value: string) => {
    setEditor((e) => ({ ...e, raw: { ...e.raw, [key]: value } }));
  }, []);
  const clearText = useCallback((prefix: string) => {
    setEditor((e) => ({ ...e, raw: Object.fromEntries(Object.entries(e.raw).filter(([key]) => !key.startsWith(prefix))) }));
  }, []);
  const acceptCollection = useCallback((submittedBase: string | undefined, update: (cfg: T) => T, prefixes: string[] = [], revision?: string) => {
    setEditor((e) => acknowledge(e, update, prefixes, undefined, revision, submittedBase));
  }, []);
  // Row saves acknowledge only that row. Other drafts, and typing after the
  // request started, are not part of the acknowledgement.
  const acceptRow = useCallback((submitted: ConfigSubmission<T>, update: (rows: T) => T, prefix: string, revision?: string) => {
    setEditor((e) => acknowledge(e, update, [prefix], submitted, revision));
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
    editor, cfg: editor.cfg, getBaseRevision, setCfg, adoptConfig, beginSave, failSave, reportFailure, acceptConfig,
    dirty: isDirty(editor), setText, field, clearText, acceptRow, acceptCollection,
    text: (key: string, derived: string) => editor.raw[key] ?? derived,
    conflictProps: {
      conflictRevision: editor.conflictRevision, olderView: editor.olderView, revisionRequired: editor.revisionRequired,
      onKeep: () => setEditor(keepEdits),
    },
  };
}

export function ConfigEditNotice({ superseded, conflictRevision, olderView, revisionRequired, onKeep, onReload }: {
  superseded: boolean; conflictRevision?: string; olderView?: boolean; revisionRequired?: boolean; onKeep?: () => void; onReload?: () => void;
}) {
  return revisionRequired ? (
    <div role="alert" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
      <p>Configuration revision unavailable. Reload before saving.</p>
      <button className="mt-2 rounded-xs border px-3 py-1.5" onClick={onReload}>Reload</button>
    </div>
  ) : conflictRevision ? (
    <div role="alert" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
      <p>Configuration changed since you loaded it</p>
      <p className="mt-1 text-xs">Your edits are kept. Reload discards them; keeping them requires review and another Save.</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <button className="rounded-xs border px-3 py-1.5" onClick={onReload}>Reload</button>
        <button className="rounded-xs border px-3 py-1.5" onClick={onKeep}>Keep my edits</button>
      </div>
    </div>
  ) : olderView ? (
    <p role="status" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">Based on an older view — review, then save again.</p>
  ) : superseded ? (
    <p role="status" aria-label="Unsaved edits" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-xs text-amber">
      Unsaved edits kept: settings changed on the server while you were editing. Review before saving; Refresh discards your edits.
    </p>
  ) : null;
}

export type ConfigFields = Pick<ReturnType<typeof useConfigEditor<unknown>>, "field" | "clearText">;
