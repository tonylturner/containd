"use client";

export const severityVariant = (sev: string) => {
  switch (sev) {
    case "critical": return "error" as const;
    case "high": return "warning" as const;
    case "medium": return "info" as const;
    default: return "neutral" as const;
  }
};

export function DetailSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-b px-4 py-3">
      <div className="mb-2 flex items-center gap-2 text-[9px] font-medium uppercase tracking-[2px] text-(--text-dim)">
        {label}
        <span className="flex-1 h-px" />
      </div>
      <div className="space-y-1.5">{children}</div>
    </div>
  );
}

export function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-3 text-xs">
      <span className="text-(--text-dim) shrink-0">{label}</span>
      <span className={`text-right text-(--text) break-all ${mono ? "font-mono text-[11px]" : ""}`}>{value}</span>
    </div>
  );
}
