export type DiffLine = { type: "add" | "del" | "same"; line: string };

// Bound CPU as well as memory. Above this budget, show the entire changed
// middle as a replacement; common prefixes and suffixes are still retained.
const MAX_DIFF_CELLS = 1_000_000;

// Propagate the exact traceback's crossing at the middle row. Unlike choosing
// an arbitrary optimal LCS split, this preserves diagonal matches and the old
// add-on-tie ordering, even for repeated lines. Only two linear rows are live.
function crossing(a: string[], b: string[], a0: number, a1: number, b0: number, b1: number): number {
  const width = b1 - b0;
  const middle = Math.floor((a1 - a0) / 2);
  const scores = new Uint32Array(width + 1);
  const origins = Uint32Array.from({ length: width + 1 }, (_, j) => j);
  for (let i = 1; i <= a1 - a0; i++) {
    let diagonal = 0;
    let diagonalOrigin = origins[0];
    for (let j = 1; j <= width; j++) {
      const above = scores[j];
      const aboveOrigin = origins[j];
      if (a[a0 + i - 1] === b[b0 + j - 1]) {
        scores[j] = diagonal + 1;
        origins[j] = i > middle ? diagonalOrigin : j;
      } else if (scores[j - 1] >= above) {
        scores[j] = scores[j - 1];
        origins[j] = i > middle ? origins[j - 1] : j;
      } else if (i <= middle) {
        origins[j] = j;
      }
      diagonal = above;
      diagonalOrigin = aboveOrigin;
    }
  }
  return b0 + origins[width];
}

function appendRange(out: DiffLine[], lines: string[], start: number, end: number, type: DiffLine["type"]) {
  for (let i = start; i < end; i++) out.push({ type, line: lines[i] });
}

function trace(out: DiffLine[], a: string[], b: string[], a0: number, a1: number, b0: number, b1: number) {
  if (a0 === a1) {
    appendRange(out, b, b0, b1, "add");
  } else if (b0 === b1) {
    appendRange(out, a, a0, a1, "del");
  } else if (a1 - a0 === 1) {
    let match = b1 - 1;
    while (match >= b0 && b[match] !== a[a0]) match--;
    if (match < b0) {
      out.push({ type: "del", line: a[a0] });
      appendRange(out, b, b0, b1, "add");
    } else {
      appendRange(out, b, b0, match, "add");
      out.push({ type: "same", line: a[a0] });
      appendRange(out, b, match + 1, b1, "add");
    }
  } else {
    // crossing's rows are released before recursing: O(a.length+b.length)
    // total space including the output, O(a.length*b.length) work.
    const split = crossing(a, b, a0, a1, b0, b1);
    const middle = a0 + Math.floor((a1 - a0) / 2);
    trace(out, a, b, a0, middle, b0, split);
    trace(out, a, b, middle, a1, split, b1);
  }
}

export function diffLines(a: string[], b: string[]): DiffLine[] {
  let prefix = 0;
  while (prefix < a.length && prefix < b.length && a[prefix] === b[prefix]) prefix++;
  let suffix = 0;
  while (suffix < a.length - prefix && suffix < b.length - prefix &&
    a[a.length - 1 - suffix] === b[b.length - 1 - suffix]) suffix++;
  const aEnd = a.length - suffix;
  const bEnd = b.length - suffix;
  const out: DiffLine[] = [];
  appendRange(out, a, 0, prefix, "same");
  if ((aEnd - prefix) * (bEnd - prefix) > MAX_DIFF_CELLS) {
    appendRange(out, a, prefix, aEnd, "del");
    appendRange(out, b, prefix, bEnd, "add");
  } else {
    trace(out, a, b, prefix, aEnd, prefix, bEnd);
  }
  appendRange(out, a, aEnd, a.length, "same");
  return out;
}
