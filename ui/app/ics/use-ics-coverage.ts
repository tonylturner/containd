"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { getRulesetPreview, isAdmin } from "../../lib/api";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import { coverageViewFromPreview, type ICSCoverageView } from "./ics-coverage-model";

/**
 * Loads candidate and applied ICS coverage from the ruleset preview, which is
 * admin-only. Loads on mount and after every staged or committed config change;
 * a stale response from an earlier load never replaces a newer one.
 */
export function useICSCoverage(): { view: ICSCoverageView; reload: () => Promise<void> } {
  const [view, setView] = useState<ICSCoverageView>({ status: "loading" });
  const generation = useRef(0);

  const reload = useCallback(async () => {
    const current = ++generation.current;
    if (!isAdmin()) {
      setView({ status: "restricted" });
      return;
    }
    const res = await getRulesetPreview();
    if (current !== generation.current) return;
    setView(res.ok ? coverageViewFromPreview(res.data) : { status: "unavailable", error: res.error });
  }, []);

  useConfigRefresh(reload);
  useEffect(() => {
    void reload();
  }, [reload]);

  return { view, reload };
}
