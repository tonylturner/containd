import type { IDSRule } from "../../lib/api";

export const FORMAT_OPTIONS = [
  { value: "", label: "Auto-detect" },
  { value: "suricata", label: "Suricata" },
  { value: "snort", label: "Snort" },
  { value: "yara", label: "YARA" },
  { value: "sigma", label: "Sigma" },
] as const;

export const EXPORT_FORMATS = [
  { value: "suricata", label: "Suricata (.rules)", ext: ".rules" },
  { value: "snort", label: "Snort (.rules)", ext: ".rules" },
  { value: "yara", label: "YARA (.yar)", ext: ".yar" },
  { value: "sigma", label: "Sigma (.yml)", ext: ".yml" },
] as const;

export const PAGE_SIZES = [10, 25, 50, 100];

const FORMAT_BADGE_COLOR: Record<string, string> = {
  suricata: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
  snort: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  yara: "text-purple-400 bg-purple-500/10 border-purple-500/20",
  sigma: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  native: "text-amber-400 bg-amber-500/10 border-amber-500/20",
};

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export type AdvancedFilters = {
  format: string;
  severity: string;
  proto: string;
  status: string;
};

export const EMPTY_FILTERS: AdvancedFilters = {
  format: "",
  severity: "",
  proto: "",
  status: "",
};

export function isRuleEnabled(r: IDSRule): boolean {
  return r.enabled === undefined || r.enabled === null || r.enabled === true;
}

export function ruleMatchesFilter(r: IDSRule, q: string): boolean {
  return (
    r.id.toLowerCase().includes(q) ||
    (r.title ?? "").toLowerCase().includes(q) ||
    (r.message ?? "").toLowerCase().includes(q) ||
    (r.proto ?? "").toLowerCase().includes(q) ||
    (r.severity ?? "").toLowerCase().includes(q) ||
    (r.sourceFormat ?? "").toLowerCase().includes(q) ||
    (r.description ?? "").toLowerCase().includes(q)
  );
}

export function ruleMatchesAdvanced(
  r: IDSRule,
  filters: AdvancedFilters,
): boolean {
  if (filters.format && (r.sourceFormat ?? "native") !== filters.format) {
    return false;
  }
  if (filters.severity && (r.severity ?? "low") !== filters.severity) {
    return false;
  }
  if (filters.proto && (r.proto ?? "") !== filters.proto) {
    return false;
  }
  if (filters.status === "enabled" && !isRuleEnabled(r)) {
    return false;
  }
  if (filters.status === "disabled" && isRuleEnabled(r)) {
    return false;
  }
  return true;
}

export function groupFilterMatch(r: IDSRule, filter: string): boolean {
  const parts = filter.split(/\s+AND\s+/i);
  return parts.every((p) => {
    const [key, val] = p.split(":");
    if (!key || !val) {
      return true;
    }
    const k = key.trim().toLowerCase();
    const v = val.trim().toLowerCase();
    switch (k) {
      case "proto":
        return (r.proto ?? "").toLowerCase() === v;
      case "format":
      case "sourceformat":
        return (r.sourceFormat ?? "native").toLowerCase() === v;
      case "severity":
        return (r.severity ?? "low").toLowerCase() === v;
      case "kind":
        return (r.kind ?? "").toLowerCase() === v;
      default:
        return (
          r.id.toLowerCase().includes(v) ||
          (r.title ?? "").toLowerCase().includes(v)
        );
    }
  });
}

export function FormatBadge({ format }: { format?: string }) {
  const f = format || "native";
  const color = FORMAT_BADGE_COLOR[f] ?? FORMAT_BADGE_COLOR.native;
  return (
    <span
      className={`inline-block rounded-sm border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ${color}`}
    >
      {f}
    </span>
  );
}
