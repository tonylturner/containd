"use client";

import { useEffect, useRef } from "react";
import { subscribeConfigChanges } from "./config-events";

/** Keep the subscription stable while always calling the current editor loader. */
export function useConfigRefresh(refresh: () => unknown) {
  const latest = useRef(refresh);
  useEffect(() => { latest.current = refresh; });
  useEffect(() => subscribeConfigChanges(() => { void latest.current(); }), []);
}
