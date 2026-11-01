"use client";

import { useCallback, useRef, useState } from "react";
import type { ApiResult, ConfigSnapshot } from "./api";
import { ConfigEditNotice, isRevisionConflict, isRevisionRequired } from "./use-config-editor";

/** Sections used together must describe one state, not a torn view. */
export function matchingRevisions(...snapshots: (ConfigSnapshot<unknown> | null)[]): boolean {
  return snapshots.length > 0 && snapshots.every(snapshot => snapshot != null && snapshot.revision === snapshots[0]?.revision);
}

/** A view's base is pinned until an explicit discard/review. Independent
 * editors can keep their own base; a background read is never consent.
 */
export function useConfigRevision() {
  const base = useRef<string | undefined>(undefined);
  const [conflict, setConflict] = useState<string>();
  const [olderView, setOlderView] = useState(false);
  const [revisionRequired, setRevisionRequired] = useState(false);
  const readConfig = useCallback(<T,>(snapshot: ConfigSnapshot<T> | null, keepEdits = true): T | null => {
    if (!snapshot) return null;
    if (!base.current || !keepEdits) {
      base.current = snapshot.revision;
      setConflict(undefined);
      setOlderView(false);
      setRevisionRequired(false);
    }
    return snapshot.data;
  }, []);
  const expectedRevision = useCallback(() => base.current ?? "", []);
  const acceptRevision = useCallback((submittedBase: string, revision?: string) => {
    if (revision && base.current === submittedBase) {
      base.current = revision;
      setOlderView(false);
      setConflict(undefined);
    }
  }, []);
  const handleRevision = useCallback(<T,>(result: ApiResult<T>): ApiResult<T> => {
    if (!result.ok && isRevisionConflict(result)) setConflict(result.currentRevision);
    if (!result.ok && isRevisionRequired(result)) setRevisionRequired(true);
    return result;
  }, []);
  const revisionNotice = (reload: () => unknown) => (
    <ConfigEditNotice superseded={false} conflictRevision={conflict} olderView={olderView} revisionRequired={revisionRequired}
      onReload={() => { void reload(); }}
      onKeep={() => { if (conflict) { base.current = conflict; setConflict(undefined); setOlderView(true); } }} />
  );
  return { readConfig, expectedRevision, acceptRevision, handleRevision, revisionNotice };
}
