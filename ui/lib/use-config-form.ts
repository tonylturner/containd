"use client";

import { useCallback, useState, type SetStateAction } from "react";
import { sameConfig } from "./config-editor";
import type { ApiResult, ConfigSnapshot } from "./api";
import type { ConfigBase, ConfigTarget } from "./config-boundary";
import { useConfigEditor } from "./use-config-editor";

/** Fields are local drafts; context is server-owned and can change only through
 * a coherent read or the same acknowledgement boundary as the fields' base. */
export function useConfigForm<F extends object, C = unknown>(initial: F, context: C = null as C, revision?: string) {
  const [defaults] = useState(initial);
  const draft = useConfigEditor({ fields: initial, context }, !!revision, revision);
  const { readConfig: read, write: mutate } = draft;
  const readConfig = useCallback((snapshot: ConfigSnapshot<C> | null, keep = true) => {
    return read(snapshot ? { data: { fields: defaults, context: snapshot.data }, revision: snapshot.revision } : null, keep);
  }, [read, defaults]);
  function clearFields(submitted: F, keys: (keyof F)[]) {
    draft.setCfg(view => {
      const fields = { ...view.fields };
      for (const key of keys) if (sameConfig(fields[key], submitted[key])) fields[key] = defaults[key];
      return { ...view, fields };
    });
  }
  function write<R>(send: (base: ConfigBase, context: C) => Promise<ApiResult<R> | null>, keys: (keyof F)[] = [], options: {
    context?: (view: C, result: R) => C; targets?: ConfigTarget<R>[];
  } = {}) {
    return mutate((base, view) => send(base, view.context), {
      patch: (view, data, submitted) => {
        const fields = { ...view.fields };
        for (const key of keys) if (sameConfig(fields[key], submitted.fields[key])) fields[key] = defaults[key];
        return { fields, context: options.context ? options.context(view.context, data) : view.context };
      }, targets: options.targets,
    });
  }
  function field<K extends keyof F>(key: K): [F[K], (value: SetStateAction<F[K]>) => void] {
    return [draft.cfg.fields[key], value => draft.setCfg(view => ({ ...view, fields: { ...view.fields,
      [key]: typeof value === "function" ? (value as (v: F[K]) => F[K])(view.fields[key]) : value,
    } }))];
  }
  return { editor: draft.editor, context: draft.cfg.context, field, readConfig, write,
    clearFields, requireReview: draft.requireReview, conflictProps: draft.conflictProps,
    collection: draft.collection, stale: draft.stale, writable: draft.writable };
}
