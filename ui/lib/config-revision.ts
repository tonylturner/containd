import type { ApiFailure } from "./api";

export type ConfigRevision = {
  baseRevision?: string;
  serverRevision?: string;
  conflictRevision?: string;
  olderView?: boolean;
  revisionRequired?: boolean;
};

export function revisionFrom(baseRevision?: string): ConfigRevision {
  return { baseRevision, serverRevision: baseRevision, conflictRevision: undefined, olderView: false, revisionRequired: false };
}

export function isRevisionConflict(failure: ApiFailure): boolean {
  return failure.status === 412 && failure.code === "config_revision_mismatch";
}

export function isRevisionRequired(failure: ApiFailure): boolean {
  return failure.status === 428 && failure.code === "config_revision_required";
}

export function revisionFailure<T extends ConfigRevision>(state: T, failure: ApiFailure): T {
  if (isRevisionConflict(failure)) return failure.currentRevision
    ? { ...state, conflictRevision: failure.currentRevision }
    : { ...state, revisionRequired: true };
  return isRevisionRequired(failure) ? { ...state, revisionRequired: true } : state;
}

/** Reads may move a clean view, but never consent to rebase retained edits. */
export function readRevision<T extends ConfigRevision>(state: T, revision: string | undefined, retain: boolean): T {
  return retain
    ? { ...state, serverRevision: revision }
    : { ...state, ...revisionFrom(revision) };
}

export function keepRevision<T extends ConfigRevision>(state: T): T {
  return state.conflictRevision ? {
    ...state, baseRevision: state.conflictRevision, conflictRevision: undefined, olderView: true,
  } : state;
}

/** CAS acknowledges only the view that submitted the write. Never install an
 * old response beneath a newer read's revision. */
export function canAcknowledge(base: string | undefined, submitted: string | undefined, revision?: string): boolean {
  return base === submitted && !!revision;
}

export function acknowledgeRevision<T extends ConfigRevision>(state: T, submitted: string | undefined, revision?: string): T {
  return canAcknowledge(state.baseRevision, submitted, revision) ? readRevision(state, revision, false) : state;
}
