"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { useToast } from "../components/ToastProvider";
import type { ApiResult } from "../lib/api";

export type SaveState = "idle" | "saving" | "saved" | "error";

/** How long "saved" or "error" shows before the state line returns to idle. */
const SETTLE_MS = 1500;

/**
 * Runs one save at a time. While an action is in flight `pending` names it,
 * so its button can be disabled, and a second run is refused even before
 * that render lands. The outcome is confirmed with a toast and `state`; a
 * failure carries the server's error, or `failure` when it gave none.
 * `run` resolves to null when it refused to start.
 */
export function useSaveAction<K extends string = "save">() {
  const toast = useToast();
  const [state, setState] = useState<SaveState>("idle");
  const [pending, setPending] = useState<K | null>(null);
  const inFlight = useRef(false);
  const settle = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (settle.current) clearTimeout(settle.current);
  }, []);

  const run = useCallback(
    async <T,>(
      key: K,
      action: () => Promise<ApiResult<T>>,
      messages: { success: string; failure: string },
    ): Promise<ApiResult<T> | null> => {
      if (inFlight.current) return null;
      inFlight.current = true;
      if (settle.current) clearTimeout(settle.current);
      setPending(key);
      setState("saving");
      let result: ApiResult<T>;
      try {
        result = await action();
      } finally {
        inFlight.current = false;
        setPending(null);
      }
      settle.current = setTimeout(() => setState("idle"), SETTLE_MS);
      if (!result.ok) {
        const error = result.error || messages.failure;
        setState("error");
        toast(error, "error");
        return { ok: false, error };
      }
      setState("saved");
      toast(result.warning ? `${messages.success} Warning: ${result.warning}` : messages.success, "success");
      return result;
    },
    [toast],
  );

  return { state, pending, run };
}
