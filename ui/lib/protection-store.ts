import { isProtectionToken, type ProtectionStatus } from "./api-protection";

/** Trust material can change the runtime target without changing configuration CAS. */
export const PROTECTION_TARGET_CHANGED = "containd:protection:target-changed";

export const UNKNOWN_PROTECTION: ProtectionStatus = {
  bootId: "", applyId: "", installedApplyId: "", runningRevision: "", mode: "", installed: null,
  desiredRevision: null, appliedRevision: null, protectingRevision: null, ready: false,
  state: "unknown", retryable: false, observedAt: "", components: [], effects: [], subsystems: [],
};
export type ProtectionView = { status?: ProtectionStatus; retrying: boolean; retryMessage?: string };

const trustTargets = (status?: ProtectionStatus) => JSON.stringify(status?.subsystems.map(s => [s.name, s.desiredTrustRevision]).sort(([a], [b]) => (a ?? "").localeCompare(b ?? "")));

/** Tokens are equality-only. Request sequence, not timestamps or revisions, orders responses. */
export function sameProtectionTarget(a: ProtectionStatus | undefined, b: ProtectionStatus | undefined) {
  return a?.bootId === b?.bootId && a?.applyId === b?.applyId && a?.desiredRevision === b?.desiredRevision
    && trustTargets(a) === trustTargets(b);
}

export function reduceProtection(current: ProtectionView, status: ProtectionStatus, sequence: number, latest: number): ProtectionView {
  if (sequence !== latest) return current;
  // Replace the entire observation, including on new boots and missing telemetry.
  return { status, retrying: current.retrying,
    retryMessage: sameProtectionTarget(current.status, status) ? current.retryMessage : undefined };
}

export function canRetryProtection(status?: ProtectionStatus) {
  return !!status && isProtectionToken(status.bootId)
    && isProtectionToken(status.applyId) && isProtectionToken(status.desiredRevision)
    && (status.retryable || status.subsystems.some(s => s.retryable));
}

export function protectionOutstanding(status?: ProtectionStatus) {
  return status?.state === "pending" || status?.subsystems.some(s => s.retryable || s.state === "pending" || s.nextRetryAt !== null);
}
