import type { ConfigBundle } from "../../lib/api";
import type { ConfigDiff } from "../../lib/api-config";
import { effectiveICSDecoders } from "../firewall/firewall-utils";
import type { BlockKey } from "./config-block-explorer";

export type Tab = "overview" | "running" | "candidate" | "diff";

export type DiffLine = { type: "add" | "del" | "same"; line: string };

export type DiffBlock = {
  key: string;
  label: string;
  diff: DiffLine[];
  hiddenChanges: boolean;
  idsBank?: ConfigDiff["idsBank"];
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
    label: "Running config",
    description: "Last committed desired state; check live status for enforcement.",
  },
  candidate: {
    label: "Staged config",
    description: "Candidate changes waiting for commit.",
  },
  diff: {
    label: "Review changes",
    description: "Compare staged changes against the running config.",
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

// The API compares sections before redaction. JSON here supplies display lines
// only: it must never decide whether a section changed.
const SECTION_LABELS: Record<string, string> = {
  system: "System",
  zones: "Zones",
  interfaces: "Interfaces",
  routing: "Routing",
  firewall: "Firewall",
  assets: "Assets",
  objects: "Objects",
  ids: "IDS",
  services: "Services",
  dataplane: "Data plane",
  export: "Export",
  pcap: "PCAP",
};

export function buildDiffBlocks(response: ConfigDiff | null | undefined): DiffBlock[] {
  if (!response?.changed || !response.candidate) {
    return [];
  }
  const running = response.running as Record<string, unknown> | null;
  const candidate = response.candidate as Record<string, unknown>;
  return response.changedSections.map((key) => {
    const runningText = JSON.stringify(running?.[key] ?? null, null, 2);
    const candidateText = JSON.stringify(candidate[key] ?? null, null, 2);
    const bankChanged = key === "ids" && (
      response.idsBank.running.count !== response.idsBank.candidate.count ||
      response.idsBank.running.sha256 !== response.idsBank.candidate.sha256
    );
    return {
      key,
      label: Object.hasOwn(SECTION_LABELS, key) ? SECTION_LABELS[key] : key,
      diff: diffLines(runningText.split("\n"), candidateText.split("\n")).filter(
        (line) => line.type !== "same",
      ),
      hiddenChanges: runningText === candidateText && !bankChanged,
      idsBank: bankChanged ? response.idsBank : undefined,
    };
  });
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
        dpiIcsProtocols: effectiveICSDecoders(cfg.dataplane?.dpiIcsProtocols),
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
