"use client";

import React from "react";

type KPIProps = {
  label: string;
  value: string | number;
  hint?: string;
  accent?: "primary" | "success" | "warning" | "error";
};

export function KPI({ label, value, hint, accent = "primary" }: KPIProps) {
  const accentClass =
    accent === "success"
      ? "text-[var(--success)]"
      : accent === "warning"
        ? "text-[var(--warning)]"
        : accent === "error"
          ? "text-[var(--error)]"
          : "text-[var(--primary)]";
  return (
    <div className="rounded-xl border border-white/10 bg-[var(--surface)] p-4 shadow-lg backdrop-blur transition-all duration-200 hover:border-[var(--primary)]/40 hover:shadow-[0_10px_40px_rgba(0,0,0,0.4)]">
      <div className="text-xs uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      <div className={`mt-1 text-3xl font-bold ${accentClass}`}>{value}</div>
      {hint && <div className="text-xs text-[var(--text-muted)]">{hint}</div>}
    </div>
  );
}
