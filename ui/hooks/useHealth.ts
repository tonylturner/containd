"use client";

import { useSyncExternalStore } from "react";

import { fetchHealth, type HealthResponse } from "../lib/api";

/** Matches the ConfigStatusBar poll. */
export const HEALTH_POLL_MS = 30_000;

// One GET /health poll shared by every component on the page: the shell's
// recovery banner and any page indicator read the same snapshot.
let snapshot: HealthResponse | undefined;
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | null = null;
let inflight: AbortController | null = null;

async function poll() {
  inflight?.abort();
  const controller = new AbortController();
  inflight = controller;
  let next: HealthResponse | undefined;
  try {
    next = (await fetchHealth(controller.signal)) ?? undefined;
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") return;
    next = undefined;
  }
  if (inflight !== controller) return;
  inflight = null;
  snapshot = next;
  listeners.forEach((notify) => notify());
}

function subscribe(notify: () => void): () => void {
  listeners.add(notify);
  if (listeners.size === 1) {
    void poll();
    timer = setInterval(() => {
      if (!document.hidden) void poll();
    }, HEALTH_POLL_MS);
  }
  return () => {
    listeners.delete(notify);
    if (listeners.size > 0) return;
    if (timer) clearInterval(timer);
    timer = null;
    inflight?.abort();
    inflight = null;
  };
}

/** Runtime health, polled while any component reads it; undefined while unknown. */
export function useHealth(): HealthResponse | undefined {
  return useSyncExternalStore(subscribe, () => snapshot, () => undefined);
}
