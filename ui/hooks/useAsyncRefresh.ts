"use client";

import { useCallback, useEffect, useEffectEvent, useState } from "react";

/**
 * Load on mount (and when the memoized loader changes), then expose the same
 * awaitable operation to buttons, config subscriptions and polling callbacks.
 * Loading starts in the initial render, not in an effect. Loaders own their
 * data/error handling and should only update state after awaiting their IO.
 * Initial arguments need not be those used by later refreshes. A factory can
 * receive the mount request's AbortSignal; it is aborted on cleanup.
 */
export function useAsyncRefresh<A extends unknown[]>(
  load: (...args: A) => Promise<void>,
  options?: { initialArgs: NoInfer<A> | ((signal: AbortSignal) => NoInfer<A>) },
) {
  const [completedLoad, setCompletedLoad] = useState<typeof load | null>(null);
  const [pending, setPending] = useState(0);
  const loadInitially = useEffectEvent((signal: AbortSignal) => {
    const args = options
      ? typeof options.initialArgs === "function" ? options.initialArgs(signal) : options.initialArgs
      : [] as unknown as A;
    return load(...args);
  });

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    void loadInitially(controller.signal).finally(() => {
      if (active) setCompletedLoad(() => load);
    });
    return () => { active = false; controller.abort(); };
  }, [load]);

  const refresh = useCallback(async (...args: A) => {
    setPending((count) => count + 1);
    try {
      await load(...args);
    } finally {
      setPending((count) => count - 1);
    }
  }, [load]);

  return {
    initialLoading: completedLoad !== load,
    loading: completedLoad !== load || pending > 0,
    refresh,
  };
}
