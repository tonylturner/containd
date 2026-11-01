"use client";

import { useCallback } from "react";
import type { ConfigSnapshot } from "./api";
import { ConfigEditNotice, useConfigEditor } from "./use-config-editor";

/** Sections used together must describe one state, not a torn view. */
export function matchingRevisions(...snapshots: (ConfigSnapshot<unknown> | null)[]): boolean {
  return snapshots.length > 0 && snapshots.every(snapshot => snapshot != null && snapshot.revision === snapshots[0]?.revision);
}

/** A server-owned view has no public payload or revision setters. Mutation
 * projections are registered before sending, never after awaiting a response. */
export function useConfigView<T>(initial: T, revision?: string) {
  const draft = useConfigEditor(initial, !!revision, revision);
  const { readConfig: read } = draft;
  const readConfig = useCallback((snapshot: ConfigSnapshot<T> | null, keep = true, hasDraft = false) => read(snapshot, keep, hasDraft), [read]);
  const revisionNotice = (reload: () => unknown) => (
    <ConfigEditNotice superseded={false} {...draft.conflictProps} onReload={() => { void reload(); }} />
  );
  return { data: draft.cfg, state: draft.editor, readConfig, write: draft.write,
    writeRefresh: draft.writeRefresh, collection: draft.collection, writer: draft.writer, stale: draft.stale,
    available: draft.available, writable: draft.writable, requireReview: draft.requireReview, revisionNotice };
}
