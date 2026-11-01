import type { ApiResult, ConfigSnapshot } from "./api";
import { accept, acceptCollection, adopt, beginSave, failSave, fresh, isDirty, keepEdits, sameConfig, type ConfigEditor, type ConfigSubmission } from "./config-editor";
import { canAcknowledge, requireRevisionReview, revisionFailure } from "./config-revision";

const acknowledge = Symbol("acknowledge-config");
declare const submittedRevision: unique symbol;
/** Only a boundary can capture a wire base. It is not an editable page value. */
export type ConfigBase = string & { readonly [submittedRevision]: true };

/** A dependent view can describe its projection, but only write() can deliver an
 * acknowledgement. No page can supply a submitted base or fabricate a receipt. */
export type ConfigTarget<R> = {
  [acknowledge]: (base: string | undefined, result: R, revision: string) => void;
};
export type ConfigWrite<T, R> = ({
  replace: (data: R, submitted: T) => T;
  patch?: never;
} | {
  patch: (view: T, data: R, submitted: T) => T;
  replace?: never;
}) & {
  prefixes?: string[];
  raw?: Record<string, string>;
  targets?: ConfigTarget<R>[];
};
export type ConfigWriteResult<R> = ApiResult<R> & { adopted?: boolean; unchanged?: boolean };

/** The sole owner of a server view and its write base. Local edits are separate
 * from reads and acknowledgements. All transitions notify atomically, including
 * before React renders; consecutive actions cannot observe a half-adopted view. */
export class ConfigBoundary<T> {
  private value: ConfigEditor<T>;
  private loaded: boolean;
  private available: boolean;
  private staleRevision?: string;
  private obligation?: { before: T; reconcile?: (view: T, before: T, next: T) => T };
  private listeners = new Set<() => void>();

  constructor(initial: T, loaded = true, revision?: string) {
    this.value = fresh(initial, revision);
    this.loaded = loaded && !!revision;
    this.available = loaded && !!revision;
  }
  snapshot = (): Readonly<ConfigEditor<T>> => this.value;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  private install(value: ConfigEditor<T>) {
    this.value = value;
    for (const listener of this.listeners) listener();
  }
  get stale() { return !!this.staleRevision; }
  get readable() { return this.available; }
  get writable() { return this.available && !!this.value.baseRevision && !this.value.revisionRequired && !this.stale; }
  edit = (update: (view: T) => T) => this.install({ ...this.value, cfg: update(this.value.cfg) });
  editRaw = (update: (raw: Record<string, string>) => Record<string, string>) =>
    this.install({ ...this.value, raw: update(this.value.raw) });
  keep = () => this.install(keepEdits(this.value));
  requireReview = (revision?: string) => this.install(requireRevisionReview(this.value, revision));

  read = (snapshot: ConfigSnapshot<T> | null, keep = true, hasDraft = false) => {
    if (!snapshot?.revision) {
      this.available = false;
      this.install({ ...this.value });
      return null;
    }
    // A stale counts-only acknowledgement is reconciled only by its payload.
    // Explicit Reload can instead discard the draft and read a newer authority.
    if (this.staleRevision && keep && snapshot.revision !== this.staleRevision) return null;
    const reconcile = this.obligation?.reconcile;
    const before = this.obligation?.before;
    const editor = keep && this.staleRevision && reconcile ? {
      ...this.value, cfg: reconcile(this.value.cfg, before!, snapshot.data),
      server: reconcile(this.value.server, before!, snapshot.data),
    } : this.value;
    this.staleRevision = undefined;
    this.obligation = undefined;
    const next = adopt(editor, snapshot.data, keep && this.loaded, snapshot.revision, hasDraft);
    this.loaded = true;
    this.available = true;
    this.install(next);
    return snapshot.data;
  };
  collection = <R,>(patch: (view: T, data: R) => T, prefixes: string[] = []): ConfigTarget<R> => ({
    [acknowledge]: (base, data, revision) => {
      this.install(acceptCollection(this.value, view => patch(view, data), prefixes, undefined, revision, base));
    },
  });

  /** A modal owns its draft's base; the parent owns its displayed collection.
   * Register the parent's projection before delegating the send to that draft.
   * The opaque base comes only from the modal's write(), never from page state. */
  writer = <A extends unknown[], R>(
    send: (base: ConfigBase, ...args: A) => Promise<ApiResult<R>>,
    patch: (view: T, data: R, ...args: A) => T,
  ) => async (base: ConfigBase, ...args: A) => {
    if (this.stale) return { ok: false as const, error: "The updated configuration must be reloaded before saving." };
    const target = this.collection((view: T, data: R) => patch(view, data, ...args));
    const result = await send(base, ...args);
    if (result?.ok && result.revision) target[acknowledge](base, result.data, result.revision);
    return result;
  };

  write = <R,>(
    send: (base: ConfigBase, submitted: T) => Promise<ApiResult<R> | null>,
    options: ConfigWrite<T, R>,
  ) => this.performWrite(send, options);

  private performWrite = async <R,>(
    send: (base: ConfigBase, submitted: T) => Promise<ApiResult<R> | null>,
    options: ConfigWrite<T, R>,
    refreshObligation?: { before: T; reconcile?: (view: T, before: T, next: T) => T },
  ): Promise<ConfigWriteResult<R>> => {
    if (this.value.revisionRequired) return {
      ok: false, status: 428, code: "config_revision_required", error: "Reload before saving.",
    };
    if (!this.writable) return { ok: false, error: "Configuration unavailable. Refresh successfully before saving." };
    const before = this.value;
    const submitted: ConfigSubmission<T> = {
      id: Symbol("config-write"), cfg: before.cfg, raw: options.raw ?? before.raw, baseRevision: before.baseRevision,
    };
    this.install(beginSave(before, submitted));
    let result: ApiResult<R>;
    try {
      const response = await send(submitted.baseRevision! as ConfigBase, submitted.cfg);
      if (!response) {
        this.install(failSave(this.value, submitted));
        return { ok: false, error: "Configuration unavailable. Refresh successfully before saving." };
      }
      result = response;
    } catch (error) {
      result = { ok: false, error: error instanceof Error ? error.message : "Network error" };
    }
    if (!result.ok) {
      const applies = this.value.baseRevision === submitted.baseRevision
        && this.value.pending.some(entry => entry.id === submitted.id);
      const settled = failSave(this.value, submitted);
      this.install(applies ? revisionFailure(settled, result) : settled);
      return result;
    }
    if (!result.revision) {
      const applies = this.value.baseRevision === submitted.baseRevision
        && this.value.pending.some(entry => entry.id === submitted.id);
      const settled = failSave(this.value, submitted);
      this.install(applies ? requireRevisionReview(settled) : settled);
      return { ...result, adopted: false };
    }
    const adopted = this.value.pending.some(entry => entry.id === submitted.id)
      && canAcknowledge(this.value.baseRevision, submitted.baseRevision, result.revision);
    // Decide whether a modal may close before installing normalized server
    // fields. Subscribers can render that installation before write() returns.
    const unchanged = sameConfig(this.value.cfg, submitted.cfg) && sameConfig(this.value.raw, submitted.raw);
    if (adopted && refreshObligation) {
      this.staleRevision = result.revision;
      this.obligation = refreshObligation;
    }
    if (options.patch) {
      this.install(acceptCollection(this.value, view => options.patch!(view, result.data, submitted.cfg),
        options.prefixes, submitted, result.revision));
    } else {
      this.install(accept(this.value, submitted, options.replace!(result.data, submitted.cfg), result.revision));
    }
    // Each dependent boundary checks the actual wire base independently.
    if (result.revision) for (const target of options.targets ?? []) {
      target[acknowledge](submitted.baseRevision, result.data, result.revision);
    }
    return { ...result, adopted, unchanged };
  };

  /** Counts/status-only writes carry a refresh obligation. Never expose an
   * advanced base with the old payload as a writable view. */
  writeRefresh = async <R,>(
    send: (base: ConfigBase, submitted: T) => Promise<ApiResult<R>>,
    refresh: () => Promise<ConfigSnapshot<T> | null>,
    reconcile?: (view: T, before: T, next: T) => T,
  ): Promise<ConfigWriteResult<R>> => {
    const before = this.value.server;
    const result = await this.performWrite(send, { patch: view => view }, { before, reconcile });
    if (!result.ok || !result.adopted || !result.revision) return result;
    const snapshot = await refresh().catch(() => null);
    // A subscription read may already have fulfilled this obligation.
    if (!this.staleRevision) return result;
    if (!snapshot) { this.read(null); return result; }
    if (snapshot.revision !== this.staleRevision) return result;
    this.read(snapshot);
    return result;
  };
  get dirty() { return isDirty(this.value); }
}
