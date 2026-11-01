"use client";

import { useCallback, useRef, useState } from "react";
import type { ApiResult, ConfigSnapshot } from "./api";
import { acknowledgeRevision, canAcknowledge, keepRevision, readRevision, revisionFailure, type ConfigRevision } from "./config-revision";
import { ConfigEditNotice } from "./use-config-editor";

/** Sections used together must describe one state, not a torn view. */
export function matchingRevisions(...snapshots: (ConfigSnapshot<unknown> | null)[]): boolean {
  return snapshots.length > 0 && snapshots.every(snapshot => snapshot != null && snapshot.revision === snapshots[0]?.revision);
}

/** Clean views follow coherent reads; retained drafts and conflict notices do
 * not rebase. Response handlers capture the base before awaiting the write. */
export function useConfigRevision() {
  const current = useRef<ConfigRevision>({});
  const [state, setState] = useState<ConfigRevision>({});
  const update = useCallback((next: ConfigRevision) => {
    current.current = next;
    setState(next);
  }, []);
  const readConfig = useCallback(<T,>(snapshot: ConfigSnapshot<T> | null, keepEdits = true, hasDraft = false): T | null => {
    if (!snapshot) return null;
    const retain = keepEdits && !!current.current.baseRevision && (hasDraft || !!current.current.conflictRevision || !!current.current.olderView || !!current.current.revisionRequired);
    update(readRevision(current.current, snapshot.revision, retain));
    return snapshot.data;
  }, [update]);
  const expectedRevision = useCallback(() => current.current.baseRevision ?? "", []);
  const handleRevision = useCallback((submittedBase: string) => <T,>(result: ApiResult<T>) => {
    const adopted = result.ok && canAcknowledge(current.current.baseRevision, submittedBase, result.revision);
    update(result.ok ? acknowledgeRevision(current.current, submittedBase, result.revision) : revisionFailure(current.current, result));
    return result.ok ? { ...result, adopted } : result;
  }, [update]);
  const requireReview = useCallback((revision: string) => update({ ...current.current, conflictRevision: revision }), [update]);
  const revisionNotice = (reload: () => unknown) => (
    <ConfigEditNotice superseded={false} {...state}
      onReload={() => { void reload(); }} onKeep={() => update(keepRevision(current.current))} />
  );
  return { readConfig, expectedRevision, handleRevision, requireReview, revisionNotice, state };
}
