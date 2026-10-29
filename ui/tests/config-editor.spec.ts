import { expect, test } from "@playwright/test";
import { accept, acceptCollection, adopt, fresh, isDirty, reconcileRows, sameConfig, upsertRow } from "../lib/config-editor";

test("background reads keep structured and raw-only edits; explicit refresh discards both", () => {
  const server = { enabled: false };
  const edited = { ...fresh(server), raw: { pools: "lan2," } };
  expect(isDirty(edited)).toBe(true);
  const changed = adopt(edited, { enabled: true });
  expect(changed.raw.pools).toBe("lan2,");
  expect(changed.superseded).toBe(true);
  expect(adopt(changed, { enabled: true }, false)).toEqual(fresh({ enabled: true }));
  expect(adopt(fresh(server), { enabled: true })).toEqual(fresh({ enabled: true }));
});

test("save echoes accept only the submitted draft, including raw-only later edits", () => {
  const submitted = { ...fresh({ enabled: false }), raw: { peers: "[]" } };
  const later = { ...submitted, raw: { peers: "[ " } };
  expect(accept(later, submitted, { enabled: false }).raw).toEqual(later.raw);
  expect(accept(submitted, submitted, { enabled: false })).toEqual(fresh({ enabled: false }));
  const structured = { ...submitted, cfg: { enabled: true } };
  expect(accept(structured, submitted, { enabled: false }).cfg.enabled).toBe(true);
});

test("wizard selections compare Set contents, not empty JSON objects", () => {
  const initial = fresh({ selected: new Set<string>() });
  expect(isDirty({ ...initial, cfg: { selected: new Set(["modbus"]) } })).toBe(true);
  expect(sameConfig(new Set(["modbus", "dnp3"]), new Set(["dnp3", "modbus"]))).toBe(true);
});

test("row acknowledgements replace or restore just the saved row", () => {
  const first = { name: "lan" }, second = { name: "wan" };
  const saved = { name: "lan", alias: "Inside" };
  expect(upsertRow([first, second], saved, (row) => row.name)).toEqual([saved, second]);
  expect(upsertRow([second], saved, (row) => row.name)).toEqual([second, saved]);
});

test("collection acknowledgements update both copies and retain unrelated structured and raw edits", () => {
  const server = [{ name: "lan", alias: "" }, { name: "wan", alias: "" }];
  const editor = {
    ...fresh(server), superseded: true,
    cfg: [{ name: "lan", alias: "pending" }, server[1]],
    raw: { '"lan".alias': '"unfinished, "', '"wan".alias': '"discard"' },
  };
  const removed = acceptCollection(editor, (rows) => rows.filter((r) => r.name !== "wan"), ['"wan".']);
  expect(removed.server).toEqual([server[0]]);
  expect(removed.cfg).toEqual([{ name: "lan", alias: "pending" }]);
  expect(removed.raw).toEqual({ '"lan".alias': '"unfinished, "' });
  const added = acceptCollection(removed, (rows) => upsertRow(rows, { name: "dmz", alias: "" }, (r) => r.name));
  expect(added.server.map((r) => r.name)).toEqual(["lan", "dmz"]);
  expect(added.cfg).toEqual([{ name: "lan", alias: "pending" }, { name: "dmz", alias: "" }]);
  expect(added.superseded).toBe(true);
});

test("row saves share collection acknowledgement but cannot clear later typing or dotted siblings", () => {
  const submitted = {
    ...fresh([{ name: "lan" }, { name: "lan.prod" }]),
    raw: { '"lan".alias': '"submitted"', '"lan.prod".alias': '"other"' },
  };
  const later = { ...submitted, raw: { ...submitted.raw, '"lan".alias': '"later"' } };
  const saved = { name: "lan", alias: "saved" };
  const update = (rows: { name: string }[]) => upsertRow(rows, saved, (r) => r.name);
  expect(acceptCollection(submitted, update, ['"lan".'], submitted).raw).toEqual({ '"lan.prod".alias': '"other"' });
  expect(acceptCollection(later, update, ['"lan".'], submitted).raw).toEqual(later.raw);
  const deleted = acceptCollection(later, (rows) => rows.filter((r) => r.name !== "lan"), ['"lan".']);
  expect(deleted.raw).toEqual({ '"lan.prod".alias': '"other"' });
});

test("a post-mutation read reconciles only changed rows even after a subscription advanced server state", () => {
  const before = [{ name: "lan", alias: "" }, { name: "wan", alias: "" }];
  const next = [before[0], { name: "wan", alias: "assigned" }, { name: "dmz", alias: "" }];
  const local = [{ name: "lan", alias: "pending" }, before[1]];
  const editor = adopt({ ...fresh(before), cfg: local }, next);
  const accepted = acceptCollection(editor, (rows) => reconcileRows(rows, before, next, (r) => r.name));
  expect(accepted.server).toEqual(next);
  expect(accepted.cfg).toEqual([local[0], next[1], next[2]]);
});
