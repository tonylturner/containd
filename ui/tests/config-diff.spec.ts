import { expect, test } from "@playwright/test";
import { diffLines, type DiffLine } from "../app/config/config-line-diff";
import { buildDiffBlocks } from "../app/config/config-utils";
import type { ConfigDiff } from "../lib/api-config";

// Frozen small-input oracle: the former quadratic traceback, including its
// prefix/suffix trimming and add-on-tie ordering for duplicate lines.
function originalDiff(a: string[], b: string[]): DiffLine[] {
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;
  let suffix = 0;
  while (suffix < a.length - prefix && suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) suffix++;
  const aa = a.slice(prefix, a.length - suffix);
  const bb = b.slice(prefix, b.length - suffix);
  const dp = Array.from({ length: aa.length + 1 }, () => new Array<number>(bb.length + 1).fill(0));
  for (let i = 1; i <= aa.length; i++) {
    for (let j = 1; j <= bb.length; j++) {
      dp[i][j] = aa[i - 1] === bb[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  const middle: DiffLine[] = [];
  let i = aa.length;
  let j = bb.length;
  while (i || j) {
    if (i && j && aa[i - 1] === bb[j - 1]) {
      middle.push({ type: "same", line: aa[--i] }); j--;
    } else if (j && (!i || dp[i][j - 1] >= dp[i - 1][j])) {
      middle.push({ type: "add", line: bb[--j] });
    } else {
      middle.push({ type: "del", line: aa[--i] });
    }
  }
  return [
    ...a.slice(0, prefix).map((line): DiffLine => ({ type: "same", line })),
    ...middle.reverse(),
    ...a.slice(a.length - suffix).map((line): DiffLine => ({ type: "same", line })),
  ];
}

test("linear-space traceback exactly matches small diffs including repeated lines", () => {
  const sequences: string[][] = [[]];
  for (let length = 1; length <= 6; length++) {
    for (let bits = 0; bits < 2 ** length; bits++) {
      sequences.push(Array.from({ length }, (_, i) => (bits & (1 << i)) ? "a" : "b"));
    }
  }
  for (const a of sequences) {
    for (const b of sequences) {
      expect(diffLines(a, b), `${a.join(",")} -> ${b.join(",")}`).toEqual(originalDiff(a, b));
    }
  }
});

test("size guard retains context and every line without a quadratic allocation", () => {
  const a = ["prefix", ...Array.from({ length: 10_000 }, (_, i) => `old-${i}`), "suffix"];
  const b = ["prefix", ...Array.from({ length: 10_000 }, (_, i) => `new-${i}`), "suffix"];
  const diff = diffLines(a, b);
  expect(diff.length).toBe(20_002);
  expect(diff[0]).toEqual({ type: "same", line: "prefix" });
  expect(diff.at(-1)).toEqual({ type: "same", line: "suffix" });
  expect(diff.filter((line) => line.type !== "add").map((line) => line.line)).toEqual(a);
  expect(diff.filter((line) => line.type !== "del").map((line) => line.line)).toEqual(b);
  expect(diffLines(a, a).every((line) => line.type === "same")).toBe(true);
});

test("section diff still reports secret-only and IDS-bank-only changes", () => {
  const idsBank = { running: { count: 1, sha256: "old" }, candidate: { count: 0, sha256: "empty" } };
  const response = {
    changed: true, changedSections: ["ids", "services"],
    running: { ids: { enabled: true }, services: {} },
    candidate: { ids: { enabled: true }, services: {} }, idsBank,
  } as unknown as ConfigDiff;
  expect(buildDiffBlocks(response)).toEqual([
    { key: "ids", label: "IDS", diff: [], hiddenChanges: false, idsBank },
    { key: "services", label: "Services", diff: [], hiddenChanges: true, idsBank: undefined },
  ]);
});
