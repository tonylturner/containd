import type { ApiFailure } from "./api";

export type ConfigRevision = {
  baseRevision?: string;
  serverRevision?: string;
  conflictRevision?: string;
  olderView?: boolean;
  revisionRequired?: boolean;
  reviewOnRead?: boolean;
};

export function revisionFrom(baseRevision?: string): ConfigRevision {
  return { baseRevision, serverRevision: baseRevision, conflictRevision: undefined, olderView: false, revisionRequired: false, reviewOnRead: false };
}

/** Even a clean view stays pinned after Keep: a background read is not consent
 * to overwrite a second operator's intervening change. An extra 412 is safer. */
export function retainRevision(state: ConfigRevision, keep: boolean, dirty: boolean): boolean {
  return keep && !!state.baseRevision && (dirty || !!state.conflictRevision || !!state.olderView || !!state.revisionRequired);
}

export function revisionError(failure: ApiFailure): string | null {
  return isRevisionConflict(failure) || isRevisionRequired(failure) ? null : failure.error;
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
  if (retain && state.reviewOnRead && revision) return { ...state, serverRevision: revision, conflictRevision: revision, revisionRequired: false, reviewOnRead: false };
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

/** Uncertain persistence needs a successful read before operator consent. */
export function requireRevisionReview<T extends ConfigRevision>(state: T, revision?: string): T {
  return { ...state, conflictRevision: revision, revisionRequired: !revision, reviewOnRead: !revision };
}
