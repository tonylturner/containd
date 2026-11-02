"use client";

import { useSyncExternalStore } from "react";
import { fetchProtection, retryProtection, type ProtectionStatus } from "../lib/api-protection";
import { PROTECTION_TARGET_CHANGED, canRetryProtection, protectionOutstanding, reduceProtection, sameProtectionTarget, UNKNOWN_PROTECTION as UNKNOWN, type ProtectionView } from "../lib/protection-store";
import { CONFIG_COMMITTED } from "../lib/config-events";

export const PROTECTION_FAST_POLL_MS = 2_000;
export const PROTECTION_POLL_MS = 30_000;
export const PROTECTION_SETTLE_MS = 10_000;

const INITIAL: ProtectionView = { retrying: false };
let snapshot: ProtectionView = INITIAL;
let fastUntil = 0;
let timer: ReturnType<typeof setTimeout> | undefined;
let inflight: AbortController | undefined;
let retryGeneration = 0;
let requestSequence = 0;
const listeners = new Set<() => void>();

function publish(next: ProtectionView) {
  snapshot = next;
  listeners.forEach((notify) => notify());
}

function schedule() {
  clearTimeout(timer);
  if (!listeners.size) return;
  const fast = protectionOutstanding(snapshot.status) || Date.now() < fastUntil;
  timer = setTimeout(() => {
    if (!document.hidden) void poll();
    else schedule();
  }, fast ? PROTECTION_FAST_POLL_MS : PROTECTION_POLL_MS);
}

async function poll() {
  const sequence = ++requestSequence;
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
  publish(reduceProtection(snapshot, status, sequence, requestSequence));
  schedule();
}

function targetChanged() {
  fastUntil = Date.now() + PROTECTION_SETTLE_MS;
  // A mutation may replace the target before the read returns. Retire all detail.
  publish({ status: UNKNOWN, retrying: snapshot.retrying });
  void poll();
}

function subscribe(notify: () => void) {
  listeners.add(notify);
  if (listeners.size === 1) {
    window.addEventListener(CONFIG_COMMITTED, targetChanged);
    window.addEventListener(PROTECTION_TARGET_CHANGED, targetChanged);
    void poll();
  }
  return () => {
    listeners.delete(notify);
    if (listeners.size) return;
    window.removeEventListener(CONFIG_COMMITTED, targetChanged);
    window.removeEventListener(PROTECTION_TARGET_CHANGED, targetChanged);
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
  if (snapshot.retrying || !canRetryProtection(observation) || !sameProtectionTarget(observation, snapshot.status)) return;
  const generation = ++retryGeneration;
  publish({ ...snapshot, retrying: true, retryMessage: undefined });
  const result = await retryProtection(observation);
  if (generation !== retryGeneration || !listeners.size) return;
  let retryMessage: string | undefined;
  if (sameProtectionTarget(observation, snapshot.status)) {
    retryMessage = result.ok ? "Retry requested; checking protection."
      : result.code === "protection_superseded" ? "Protection changed. Status refreshed; review it before retrying."
      : `Retry failed: ${result.error}`;
  }
  publish({ ...snapshot, retrying: false, retryMessage });
  fastUntil = Date.now() + PROTECTION_SETTLE_MS;
  await poll();
}
