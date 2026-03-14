import type { ConfigBundle } from "../../lib/api";
import type { BlockKey } from "./config-block-explorer";

export type Tab = "overview" | "running" | "candidate" | "diff";

export type DiffLine = { type: "add" | "del" | "same"; line: string };

export type DiffBlock = {
  key: BlockKey;
  label: string;
  running: unknown;
  candidate: unknown;
  diff: DiffLine[];
};

export type BlockItem = {
  id: string;
  label: string;
  meta: string;
};

export const TAB_META: Record<Tab, { label: string; description: string }> = {
  overview: {
    label: "Overview",
    description: "Backups, restore, and config summary.",
  },
  running: {
    label: "Live config",
    description: "What is active on the appliance now.",
  },
  candidate: {
    label: "Staged config",
    description: "Saved changes waiting to be reviewed or applied.",
  },
  diff: {
    label: "Review changes",
    description: "Compare staged changes against the live config.",
  },
};

export function parseTab(value: string | null): Tab {
  if (value && value in TAB_META) {
    return value as Tab;
  }
  return "overview";
}

export function diffLines(aLines: string[], bLines: string[]): DiffLine[] {
  const n = aLines.length;
  const m = bLines.length;
  let prefix = 0;
  while (prefix < n && prefix < m && aLines[prefix] === bLines[prefix]) {
    prefix++;
  }
  let suffix = 0;
  while (
    suffix < n - prefix &&
    suffix < m - prefix &&
    aLines[n - 1 - suffix] === bLines[m - 1 - suffix]
  ) {
    suffix++;
  }
  const aSlice = aLines.slice(prefix, n - suffix);
  const bSlice = bLines.slice(prefix, m - suffix);
  const sn = aSlice.length;
  const sm = bSlice.length;
  if (sn === 0 && sm === 0) {
    return aLines.map((line) => ({ type: "same" as const, line }));
  }
  const prefixLines: DiffLine[] = aLines
    .slice(0, prefix)
    .map((line) => ({ type: "same" as const, line }));
  const suffixLines: DiffLine[] = aLines
    .slice(n - suffix)
    .map((line) => ({ type: "same" as const, line }));
  if (sn === 0) {
    return [
      ...prefixLines,
      ...bSlice.map((line) => ({ type: "add" as const, line })),
      ...suffixLines,
    ];
  }
  if (sm === 0) {
    return [
      ...prefixLines,
      ...aSlice.map((line) => ({ type: "del" as const, line })),
      ...suffixLines,
    ];
  }

  let prev = new Array(sm + 1).fill(0);
  let curr = new Array(sm + 1).fill(0);
  for (let i = 1; i <= sn; i += 1) {
    for (let j = 1; j <= sm; j += 1) {
      if (aSlice[i - 1] === bSlice[j - 1]) {
        curr[j] = prev[j - 1] + 1;
      } else {
        curr[j] = Math.max(prev[j], curr[j - 1]);
      }
    }
    [prev, curr] = [curr, prev];
    curr.fill(0);
  }

  const dp: number[][] = Array.from({ length: sn + 1 }, () =>
    new Array(sm + 1).fill(0),
  );
  for (let i = 1; i <= sn; i += 1) {
    for (let j = 1; j <= sm; j += 1) {
      if (aSlice[i - 1] === bSlice[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  const mid: DiffLine[] = [];
  let i = sn;
  let j = sm;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && aSlice[i - 1] === bSlice[j - 1]) {
      mid.push({ type: "same", line: aSlice[i - 1] });
      i -= 1;
      j -= 1;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      mid.push({ type: "add", line: bSlice[j - 1] });
      j -= 1;
    } else if (i > 0) {
      mid.push({ type: "del", line: aSlice[i - 1] });
      i -= 1;
    }
  }
  mid.reverse();
  return [...prefixLines, ...mid, ...suffixLines];
}

export function formatBytes(size: number) {
  if (!Number.isFinite(size)) {
    return "-";
  }
  if (size < 1024) {
    return `${size} B`;
  }
  const kb = size / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }
  const mb = kb / 1024;
  if (mb < 1024) {
    return `${mb.toFixed(1)} MB`;
  }
  const gb = mb / 1024;
  return `${gb.toFixed(1)} GB`;
}

export function buildDiffBlocks(
  running: ConfigBundle | null,
  candidate: ConfigBundle | null,
): DiffBlock[] {
  if (!candidate) {
    return [];
  }
  const r = running ?? {};
  const c = candidate;
  const blocks: {
    key: BlockKey;
    label: string;
    running: unknown;
    candidate: unknown;
  }[] = [
    { key: "system", label: "System", running: (r as any).system, candidate: (c as any).system },
    { key: "zones", label: "Zones", running: (r as any).zones, candidate: (c as any).zones },
    { key: "interfaces", label: "Interfaces", running: (r as any).interfaces, candidate: (c as any).interfaces },
    { key: "routing", label: "Routing", running: (r as any).routing, candidate: (c as any).routing },
    { key: "firewall", label: "Firewall rules", running: (r as any).firewall?.rules, candidate: (c as any).firewall?.rules },
    { key: "nat", label: "NAT", running: (r as any).firewall?.nat, candidate: (c as any).firewall?.nat },
    { key: "portForwards", label: "Port forwards", running: (r as any).firewall?.portForwards, candidate: (c as any).firewall?.portForwards },
    { key: "assets", label: "Assets", running: (r as any).assets, candidate: (c as any).assets },
    { key: "objects", label: "Objects", running: (r as any).objects, candidate: (c as any).objects },
    { key: "ids", label: "IDS", running: (r as any).ids, candidate: (c as any).ids },
    { key: "services", label: "Services", running: (r as any).services, candidate: (c as any).services },
    { key: "dataPlane", label: "Data plane", running: (r as any).dataplane, candidate: (c as any).dataplane },
    {
      key: "dpi",
      label: "DPI",
      running: {
        dpiMode: (r as any).dataplane?.dpiMode,
        dpiIcsProtocols: (r as any).dataplane?.dpiIcsProtocols,
        dpiProtocols: (r as any).dataplane?.dpiProtocols,
        dpiEnabled: (r as any).dataplane?.dpiEnabled,
        dpiExclusions: (r as any).dataplane?.dpiExclusions,
      },
      candidate: {
        dpiMode: (c as any).dataplane?.dpiMode,
        dpiIcsProtocols: (c as any).dataplane?.dpiIcsProtocols,
        dpiProtocols: (c as any).dataplane?.dpiProtocols,
        dpiEnabled: (c as any).dataplane?.dpiEnabled,
        dpiExclusions: (c as any).dataplane?.dpiExclusions,
      },
    },
    { key: "export", label: "Export", running: (r as any).export, candidate: (c as any).export },
    { key: "pcap", label: "PCAP", running: (r as any).pcap, candidate: (c as any).pcap },
  ];

  return blocks
    .map((block) => {
      const same =
        JSON.stringify(block.running ?? null) ===
        JSON.stringify(block.candidate ?? null);
      if (same) {
        return null;
      }
      const runningLines = JSON.stringify(block.running ?? null, null, 2).split("\n");
      const candidateLines = JSON.stringify(block.candidate ?? null, null, 2).split("\n");
      const diff = diffLines(runningLines, candidateLines).filter(
        (line) => line.type !== "same",
      );
      return diff.length === 0 ? null : { ...block, diff };
    })
    .filter(Boolean) as DiffBlock[];
}

export function buildBlockItems(
  selectedBlock: BlockKey,
  viewerConfig: ConfigBundle | null,
): BlockItem[] {
  if (!viewerConfig) {
    return [];
  }
  const cfg = viewerConfig as any;
  switch (selectedBlock) {
    case "zones":
      return (cfg.zones ?? []).map((z: any): BlockItem => ({
        id: String(z.name),
        label: z.alias ? `${z.alias} (${z.name})` : String(z.name),
        meta: z.description || "Zone",
      }));
    case "interfaces":
      return (cfg.interfaces ?? []).map((i: any): BlockItem => ({
        id: String(i.name),
        label: i.alias ? `${i.alias} (${i.name})` : String(i.name),
        meta: [i.zone || "no zone", i.device || "no device"].join(" · "),
      }));
    case "firewall":
      return (cfg.firewall?.rules ?? []).map((r: any): BlockItem => ({
        id: String(r.id),
        label: String(r.id),
        meta: r.action ? `Action ${r.action}` : "Rule",
      }));
    case "assets":
      return (cfg.assets ?? []).map((a: any): BlockItem => ({
        id: String(a.id || a.name),
        label: String(a.name || a.id),
        meta: a.zone || a.type || "Asset",
      }));
    case "objects":
      return (cfg.objects ?? []).map((o: any): BlockItem => ({
        id: String(o.id || o.name),
        label: String(o.name || o.id),
        meta: o.type || "Object",
      }));
    case "ids":
      return (cfg.ids?.rules ?? []).map((r: any): BlockItem => ({
        id: String(r.id || r.title),
        label: String(r.title || r.id),
        meta: r.severity || "Rule",
      }));
    default:
      return [];
  }
}

export function findSelectedItem(
  selectedBlock: BlockKey,
  selectedItemId: string | null,
  viewerConfig: ConfigBundle | null,
) {
  if (!viewerConfig || !selectedItemId) {
    return null;
  }
  const cfg = viewerConfig as any;
  switch (selectedBlock) {
    case "zones":
      return (cfg.zones ?? []).find((z: any) => z.name === selectedItemId) ?? null;
    case "interfaces":
      return (cfg.interfaces ?? []).find((i: any) => i.name === selectedItemId) ?? null;
    case "firewall":
      return (cfg.firewall?.rules ?? []).find((r: any) => r.id === selectedItemId) ?? null;
    case "assets":
      return (
        (cfg.assets ?? []).find((a: any) => (a.id || a.name) === selectedItemId) ??
        null
      );
    case "objects":
      return (
        (cfg.objects ?? []).find((o: any) => (o.id || o.name) === selectedItemId) ??
        null
      );
    case "ids":
      return (
        (cfg.ids?.rules ?? []).find(
          (r: any) => (r.id || r.title) === selectedItemId,
        ) ?? null
      );
    default:
      return null;
  }
}

export function getBlockValue(
  selectedBlock: BlockKey,
  viewerConfig: ConfigBundle | null,
) {
  if (!viewerConfig) {
    return null;
  }
  const cfg = viewerConfig as any;
  switch (selectedBlock) {
    case "system":
      return cfg.system;
    case "zones":
      return cfg.zones;
    case "interfaces":
      return cfg.interfaces;
    case "routing":
      return cfg.routing;
    case "firewall":
      return cfg.firewall?.rules;
    case "nat":
      return cfg.firewall?.nat;
    case "portForwards":
      return cfg.firewall?.nat?.portForwards;
    case "assets":
      return cfg.assets;
    case "objects":
      return cfg.objects;
    case "ids":
      return cfg.ids;
    case "services":
      return cfg.services;
    case "dataPlane":
      return cfg.dataplane;
    case "dpi":
      return {
        dpiMode: cfg.dataplane?.dpiMode,
        dpiEnabled: cfg.dataplane?.dpiEnabled,
        dpiIcsProtocols: cfg.dataplane?.dpiIcsProtocols,
        dpiProtocols: cfg.dataplane?.dpiProtocols,
        dpiExclusions: cfg.dataplane?.dpiExclusions,
      };
    case "export":
      return cfg.export;
    case "pcap":
      return cfg.pcap;
    default:
      return null;
  }
}
