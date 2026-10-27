"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { getICSCoverage } from "../../lib/api";
import { useConfigRefresh } from "../../lib/use-config-refresh";
import { coverageViewFromReport, type ICSCoverageView } from "./ics-coverage-model";

/**
 * Loads candidate and applied ICS coverage, which any authenticated user can
 * read. Loads on mount and after every staged or committed config change; a
 * stale response from an earlier load never replaces a newer one.
 */
export function useICSCoverage(): { view: ICSCoverageView; reload: () => Promise<void> } {
  const [view, setView] = useState<ICSCoverageView>({ status: "loading" });
  const generation = useRef(0);

  const reload = useCallback(async () => {
    const current = ++generation.current;
    const res = await getICSCoverage();
    if (current !== generation.current) return;
    setView(res.ok ? coverageViewFromReport(res.data) : { status: "unavailable", error: res.error });
  }, []);

  useConfigRefresh(reload);
  useEffect(() => {
    void reload();
  }, [reload]);

  return { view, reload };
}
