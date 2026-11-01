"use client";

import { useCallback, useRef, useState, useSyncExternalStore, type SetStateAction } from "react";
import { sameConfig, type ConfigEditor } from "./config-editor";
import { ConfigBoundary } from "./config-boundary";

export { isRevisionConflict, isRevisionRequired, revisionError } from "./config-revision";

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
  const [boundary] = useState(() => new ConfigBoundary(
    typeof initial === "function" ? (initial as () => T)() : initial, initialLoaded, revision,
  ));
  const editor = useSyncExternalStore(boundary.subscribe, boundary.snapshot, boundary.snapshot);
  const setCfg = useCallback((update: SetStateAction<T>) => {
    boundary.edit(cfg => typeof update === "function" ? (update as (cfg: T) => T)(cfg) : update);
  }, [boundary]);
  const setText = useCallback((key: string, value: string) => {
    boundary.editRaw(raw => ({ ...raw, [key]: value }));
  }, [boundary]);
  const clearText = useCallback((prefix: string) => {
    boundary.editRaw(raw => Object.fromEntries(Object.entries(raw).filter(([key]) => !key.startsWith(prefix))));
  }, [boundary]);
  function field<V>(key: string, derived: V): [V, (value: SetStateAction<V>) => void] {
    const value = key in editor.raw ? JSON.parse(editor.raw[key]) as V : derived;
    return [value, (update) => boundary.editRaw(raw => {
      const current = key in raw ? JSON.parse(raw[key]) as V : derived;
      const next = typeof update === "function" ? (update as (v: V) => V)(current) : update;
      if (sameConfig(next, derived) && boundary.snapshot().pending.length === 0) {
        return Object.fromEntries(Object.entries(raw).filter(([name]) => name !== key));
      }
      return { ...raw, [key]: JSON.stringify(next) };
    })];
  }
  return {
    editor: editor as Readonly<Omit<ConfigEditor<T>, "server" | "pending">>, cfg: editor.cfg, setCfg, readConfig: boundary.read,
    write: boundary.write, writeRefresh: boundary.writeRefresh, collection: boundary.collection, writer: boundary.writer,
    requireReview: boundary.requireReview, dirty: boundary.dirty, stale: boundary.stale,
    available: boundary.readable, writable: boundary.writable, setText, field, clearText,
    text: (key: string, derived: string) => editor.raw[key] ?? derived,
    conflictProps: {
      conflictRevision: editor.conflictRevision, olderView: editor.olderView, revisionRequired: editor.revisionRequired,
      stale: boundary.stale, onKeep: boundary.keep,
    },
  };
}

export function ConfigEditNotice({ superseded, conflictRevision, olderView, revisionRequired, stale, onKeep, onReload }: {
  superseded: boolean; conflictRevision?: string; olderView?: boolean; revisionRequired?: boolean; stale?: boolean; onKeep?: () => void; onReload?: () => void;
}) {
  return stale ? (
    <div role="alert" className="mb-4 rounded-xs border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
      <p>Changes staged, but the updated configuration is unavailable. Reload before saving.</p>
      <button className="mt-2 rounded-xs border px-3 py-1.5" onClick={onReload}>Reload</button>
    </div>
  ) : revisionRequired ? (
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
