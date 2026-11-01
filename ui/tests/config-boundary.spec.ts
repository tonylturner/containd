import { expect, test } from "@playwright/test";
import { ConfigBoundary } from "../lib/config-boundary";
import type { ApiResult } from "../lib/api";

const r1 = "0123456789abcdef.1";
const r2 = "0123456789abcdef.2";
const r3 = "0123456789abcdef.3";

test("the boundary owns both the wire base and the atomic payload adoption", async () => {
  const view = new ConfigBoundary(["one", "two"], true, r1);
  const bases: string[] = [];
  const send = async (base: string, rows: string[]) => {
    bases.push(base);
    return { ok: true as const, data: rows.slice(1), revision: bases.length === 1 ? r2 : r3 };
  };
  await view.write(send, { replace: rows => rows });
  await view.write(send, { replace: rows => rows });
  expect(bases).toEqual([r1, r2]);
  expect(view.snapshot().cfg).toEqual([]);
  expect(view.snapshot().baseRevision).toBe(r3);
});

test("a dependent row boundary cannot acknowledge a creation from a different actual base", async () => {
  const rows = new ConfigBoundary(["operator"], true, r1);
  rows.editRaw(() => ({ labels: "mine" }));
  const create = new ConfigBoundary("", true, r2);
  await create.write(async base => {
    expect(base).toBe(r2);
    return { ok: true, data: "new", revision: r3 };
  }, { replace: () => "", targets: [rows.collection((rows, row: string) => [...rows, row])] });
  expect(rows.snapshot().baseRevision).toBe(r1);
  expect(rows.snapshot().cfg).toEqual(["operator"]);
  expect(rows.snapshot().raw).toEqual({ labels: "mine" });
});

test("a refresh overtaking an acknowledgement rejects both its payload and revision", async () => {
  const view = new ConfigBoundary(["old"], true, r1);
  let release!: (value: ApiResult<string[]>) => void;
  const pending = view.write(() => new Promise<ApiResult<string[]>>(resolve => { release = resolve; }), { replace: (data: string[]) => data });
  view.read({ data: ["remote"], revision: r3 }, false);
  release({ ok: true, data: ["late"], revision: r2 });
  expect((await pending).adopted).toBe(false);
  expect(view.snapshot().cfg).toEqual(["remote"]);
  expect(view.snapshot().baseRevision).toBe(r3);
});

test("a status-only acknowledgement blocks mutations until its payload is reconciled", async () => {
  const view = new ConfigBoundary(["old"], true, r1);
  let release!: (value: { data: string[]; revision: string }) => void;
  const pending = view.writeRefresh(async () => ({ ok: true, data: null, revision: r2 }),
    () => new Promise(resolve => { release = resolve; }));
  await expect.poll(() => view.stale).toBe(true);
  let sent = false;
  expect((await view.write(async () => { sent = true; return { ok: true, data: [], revision: r3 }; },
    { replace: (data: string[]) => data })).ok).toBe(false);
  expect(sent).toBe(false);
  release({ data: ["new"], revision: r2 });
  await pending;
  expect(view.writable).toBe(true);
  expect(view.snapshot().cfg).toEqual(["new"]);
  expect(view.snapshot().baseRevision).toBe(r2);
});

test("local draft operations never advance the server base", () => {
  const view = new ConfigBoundary({ name: "" }, true, r1);
  view.edit(() => ({ name: "site" }));
  view.edit(() => ({ name: "" }));
  expect(view.snapshot().baseRevision).toBe(r1);
  expect(view.snapshot().server).toEqual({ name: "" });
});

test("modal completion compares the submitted draft before normalizing its server context", async () => {
  const view = new ConfigBoundary({ text: "mine", context: "old" }, true, r1);
  const first = await view.write(async () => ({ ok: true, data: "new context", revision: r2 }),
    { replace: context => ({ text: "mine", context }) });
  expect(first.unchanged).toBe(true);
  let release!: (value: ApiResult<string>) => void;
  const pending = view.write(() => new Promise<ApiResult<string>>(resolve => { release = resolve; }),
    { replace: context => ({ text: "mine", context }) });
  view.edit(draft => ({ ...draft, text: "later" }));
  release({ ok: true, data: "third context", revision: r3 });
  expect((await pending).unchanged).toBe(false);
  expect(view.snapshot().cfg.text).toBe("later");
});

test("an unavailable read disables writes without discarding the pinned draft or review obligation", async () => {
  const view = new ConfigBoundary("original", true, r1);
  view.edit(() => "mine");
  view.requireReview();
  view.read(null);
  expect(view.readable).toBe(false);
  expect(view.writable).toBe(false);
  expect(view.snapshot().cfg).toBe("mine");
  view.read({ data: "remote", revision: r2 });
  expect(view.snapshot().conflictRevision).toBe(r2);
  expect(view.snapshot().baseRevision).toBe(r1);
  view.keep();
  expect(view.snapshot().baseRevision).toBe(r2);
});

test("a failed obligation read cannot enable another mutation; Reload can reconcile a newer authority", async () => {
  const view = new ConfigBoundary("old", true, r1);
  await view.writeRefresh(async () => ({ ok: true, data: null, revision: r2 }), async () => null);
  expect(view.stale).toBe(true);
  expect(view.writable).toBe(false);
  expect(view.read({ data: "third", revision: r3 })).toBeNull();
  expect(view.stale).toBe(true);
  view.read({ data: "third", revision: r3 }, false);
  expect(view.stale).toBe(false);
  expect(view.writable).toBe(true);
  expect(view.snapshot().cfg).toBe("third");
  expect(view.snapshot().baseRevision).toBe(r3);
});

test("missing acknowledgement revisions install nothing and require a read and explicit review", async () => {
  const view = new ConfigBoundary("old", true, r1);
  await view.write(async () => ({ ok: true, data: "unversioned" }), { replace: data => data });
  expect(view.snapshot().cfg).toBe("old");
  expect(view.snapshot().baseRevision).toBe(r1);
  expect(view.snapshot().revisionRequired).toBe(true);
  expect(view.writable).toBe(false);
});

test("a subscription can fulfill an import obligation without losing either additions or local edits", async () => {
  const view = new ConfigBoundary(["original"], true, r1);
  view.edit(() => ["local"]);
  let release!: (value: null) => void;
  const pending = view.writeRefresh(async () => ({ ok: true, data: { count: 1 }, revision: r2 }),
    () => new Promise(resolve => { release = resolve; }),
    (draft, before, next) => [...draft, ...next.filter(row => !before.includes(row))]);
  await expect.poll(() => view.stale).toBe(true);
  view.read({ data: ["original", "imported"], revision: r2 });
  expect(view.writable).toBe(true);
  expect(view.snapshot().cfg).toEqual(["local", "imported"]);
  expect(view.snapshot().server).toEqual(["original", "imported"]);
  release(null);
  await pending;
  expect(view.readable).toBe(true);
  expect(view.snapshot().cfg).toEqual(["local", "imported"]);
});

test("a late 412 cannot offer consent to an older conflict after Reload", async () => {
  const view = new ConfigBoundary("original", true, r1);
  let release!: (value: ApiResult<string>) => void;
  const pending = view.write(() => new Promise<ApiResult<string>>(resolve => { release = resolve; }), { replace: data => data });
  view.read({ data: "fresh", revision: r3 }, false);
  release({ ok: false, status: 412, code: "config_revision_mismatch", currentRevision: r2, error: "changed" });
  await pending;
  expect(view.snapshot().baseRevision).toBe(r3);
  expect(view.snapshot().conflictRevision).toBeUndefined();
  expect(view.snapshot().cfg).toBe("fresh");
});
