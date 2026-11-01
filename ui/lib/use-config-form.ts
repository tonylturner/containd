"use client";

import { useCallback, useRef, useState, type SetStateAction } from "react";
import { adopt, fresh, keepEdits, sameConfig, type ConfigEditor } from "./config-editor";
import { acknowledgeRevision, canAcknowledge, revisionFailure } from "./config-revision";
import type { ApiFailure } from "./api";

/** Creation/row forms keep raw fields separately from their server context. */
export function useConfigForm<F extends object>(initial: F, context: unknown = null, revision?: string) {
  const defaults = useRef(initial);
  const [editor, setEditor] = useState(() => fresh({ fields: initial, context }, revision));
  const refreshForm = useCallback((nextContext: unknown, keepEdits = true, revision?: string) => {
    setEditor((e) => {
      const next = adopt(e, { fields: defaults.current, context: nextContext }, keepEdits, revision);
      return { ...next, cfg: { ...next.cfg, context: nextContext } };
    });
  }, []);
  const acceptFields = useCallback((submitted: ConfigEditor<{ fields: F; context: unknown }>, keys: (keyof F)[], revision?: string) => {
    setEditor((e) => {
      if (!canAcknowledge(e.baseRevision, submitted.baseRevision, revision)) return e;
      const fields = { ...e.cfg.fields };
      for (const key of keys) {
        if (sameConfig(fields[key], submitted.cfg.fields[key])) fields[key] = defaults.current[key];
      }
      return { ...acknowledgeRevision(e, submitted.baseRevision, revision), cfg: { ...e.cfg, fields },
        superseded: false };
    });
  }, []);
  function field<K extends keyof F>(key: K): [F[K], (value: SetStateAction<F[K]>) => void] {
    return [editor.cfg.fields[key], (value) => setEditor((e) => ({
      ...e, cfg: { ...e.cfg, fields: { ...e.cfg.fields,
        [key]: typeof value === "function" ? (value as (v: F[K]) => F[K])(e.cfg.fields[key]) : value,
      } },
    }))];
  }
  return { editor, field, refreshForm, acceptFields,
    // Combining local drafts from different snapshots also requires explicit review.
    requireReview: (revision: string) => setEditor((e) => ({ ...e, conflictRevision: revision })),
    fail: (failure: ApiFailure) => {
      setEditor((e) => revisionFailure(e, failure));
    },
    conflictProps: {
      conflictRevision: editor.conflictRevision, olderView: editor.olderView, revisionRequired: editor.revisionRequired,
      onKeep: () => setEditor(keepEdits),
    },
  };
}
