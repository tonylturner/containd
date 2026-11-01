"use client";

import { useSyncExternalStore } from "react";
import { fetchProtection, retryProtection, type ProtectionStatus } from "../lib/api-protection";
import { CONFIG_COMMITTED } from "../lib/config-events";

export const PROTECTION_FAST_POLL_MS = 2_000;
export const PROTECTION_POLL_MS = 30_000;
export const PROTECTION_SETTLE_MS = 10_000;

const UNKNOWN: ProtectionStatus = {
  bootId: "", applyId: "", installedApplyId: "", state: "unknown", retryable: false,
  observedAt: "", components: [], effects: [],
};
type ProtectionView = { status?: ProtectionStatus; retrying: boolean; retryMessage?: string };
const INITIAL: ProtectionView = { retrying: false };
let snapshot: ProtectionView = INITIAL;
let fastUntil = 0;
let timer: ReturnType<typeof setTimeout> | undefined;
let inflight: AbortController | undefined;
let retryGeneration = 0;
const listeners = new Set<() => void>();

function publish(next: ProtectionView) {
  snapshot = next;
  listeners.forEach((notify) => notify());
}

function schedule() {
  clearTimeout(timer);
  if (!listeners.size) return;
  const fast = snapshot.status?.state === "pending" || Date.now() < fastUntil;
  timer = setTimeout(() => {
    if (!document.hidden) void poll();
    else schedule();
  }, fast ? PROTECTION_FAST_POLL_MS : PROTECTION_POLL_MS);
}

function sameApply(a: ProtectionStatus | undefined, b: ProtectionStatus | undefined) {
  return a?.bootId === b?.bootId && a?.applyId === b?.applyId;
}

async function poll() {
  inflight?.abort();
  const controller = new AbortController();
  inflight = controller;
  let status: ProtectionStatus;
  try {
    status = (await fetchProtection(controller.signal)) ?? UNKNOWN;
  } catch {
    if (controller.signal.aborted) return;
    status = UNKNOWN;
  }
  if (inflight !== controller) return;
  inflight = undefined;
  publish({
    status, retrying: snapshot.retrying,
    retryMessage: sameApply(snapshot.status, status) ? snapshot.retryMessage : undefined,
  });
  schedule();
}

function committed() {
  fastUntil = Date.now() + PROTECTION_SETTLE_MS;
  // A commit may replace the apply before the read returns. Retire all detail.
  publish({ status: UNKNOWN, retrying: snapshot.retrying });
  void poll();
}

function subscribe(notify: () => void) {
  listeners.add(notify);
  if (listeners.size === 1) {
    window.addEventListener(CONFIG_COMMITTED, committed);
    void poll();
  }
  return () => {
    listeners.delete(notify);
    if (listeners.size) return;
    window.removeEventListener(CONFIG_COMMITTED, committed);
    clearTimeout(timer);
    inflight?.abort();
    inflight = undefined;
    retryGeneration++;
    snapshot = INITIAL;
    fastUntil = 0;
  };
}

/** One immutable observation, shared by the shell, topology and page indicators. */
export function useProtection(): ProtectionView {
  return useSyncExternalStore(subscribe, () => snapshot, () => INITIAL);
}

/** Retry exactly the observation the operator saw; conflicts refresh, never replay. */
export async function requestProtectionRetry(observation: ProtectionStatus) {
  if (snapshot.retrying || !observation.retryable || !sameApply(observation, snapshot.status)) return;
  const generation = ++retryGeneration;
  publish({ ...snapshot, retrying: true, retryMessage: undefined });
  const result = await retryProtection(observation);
  if (generation !== retryGeneration || !listeners.size) return;
  let retryMessage: string | undefined;
  if (sameApply(observation, snapshot.status)) {
    retryMessage = result.ok ? "Retry requested; checking protection."
      : result.code === "protection_superseded" ? "Protection changed. Status refreshed; review it before retrying."
      : result.code === "protection_not_retryable" ? "Protection is no longer retryable. Status refreshed."
      : `Retry failed: ${result.error}`;
  }
  publish({ ...snapshot, retrying: false, retryMessage });
  fastUntil = Date.now() + PROTECTION_SETTLE_MS;
  await poll();
}
