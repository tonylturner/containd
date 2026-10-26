"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { getInstalledRulesetStatus, type InstalledRulesetStatus } from "../lib/api";
import { useConfigRefresh } from "../lib/use-config-refresh";
import { useHealth } from "./useHealth";

export type InstalledRulesetView =
  | { state: "loading" }
  | { state: "loaded"; status: InstalledRulesetStatus }
  | { state: "unavailable"; error: string };

/**
 * The installed ruleset's status, which any authenticated user can read: why
 * health reports enforcement degraded. Loads on mount, after every staged or
 * committed config change and whenever health's enforcement state or reason
 * changes; a stale response from an earlier load never replaces a newer one.
 */
export function useInstalledRuleset(): InstalledRulesetView {
  const [view, setView] = useState<InstalledRulesetView>({ state: "loading" });
  const generation = useRef(0);
  const enforcement = useHealth()?.enforcement;
  const enforcementKey = enforcement ? `${enforcement.state}\n${enforcement.reason}` : "";

  const reload = useCallback(async () => {
    const current = ++generation.current;
    const res = await getInstalledRulesetStatus();
    if (current !== generation.current) return;
    setView(res.ok ? { state: "loaded", status: res.data } : { state: "unavailable", error: res.error });
  }, []);

  useConfigRefresh(reload);
  useEffect(() => {
    void reload();
  }, [reload, enforcementKey]);

  return view;
}
