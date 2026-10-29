import { expect, test } from "@playwright/test";
import { accept, adopt, fresh, isDirty, sameConfig, upsertRow } from "../lib/config-editor";

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
