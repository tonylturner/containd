"use client";

import * as React from "react";

type BadgeVariant = "success" | "warning" | "error" | "info" | "neutral";

const variantClasses: Record<BadgeVariant, string> = {
  success: "badge-secure",
  warning: "badge-warning",
  error: "badge-critical",
  info: "bg-[rgba(6,182,212,0.15)] text-[var(--cyan)]",
  neutral: "badge-offline",
};

type StatusBadgeProps = {
  variant: BadgeVariant;
  children: React.ReactNode;
  dot?: boolean;
  className?: string;
};

export function StatusBadge({ variant, children, dot, className = "" }: StatusBadgeProps) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-sm px-2 py-0.5 font-mono text-[9px] tracking-wider uppercase ${variantClasses[variant]} ${className}`}>
      {dot && <span className={`inline-block h-1.5 w-1.5 rounded-full ${
        variant === "success" ? "bg-[var(--green)]" :
        variant === "warning" ? "bg-[var(--amber)]" :
        variant === "error" ? "bg-[var(--red)]" :
        variant === "info" ? "bg-[var(--cyan)]" :
        "bg-[var(--text-dim)]"
      }`} />}
      {children}
    </span>
  );
}

/** Larger status indicator for dashboard cards and section headers */
export function StatusIndicator({
  status,
  label,
  sublabel,
}: {
  status: "healthy" | "degraded" | "error" | "unknown";
  label: string;
  sublabel?: string;
}) {
  const colors = {
    healthy: "bg-[var(--green)]",
    degraded: "bg-[var(--amber)]",
    error: "bg-[var(--red)]",
    unknown: "bg-[var(--text-dim)]",
  };

  return (
    <div className="flex items-center gap-2.5">
      <span className={`h-2.5 w-2.5 rounded-full ${colors[status]}`} />
      <div>
        <span className="text-sm font-medium text-[var(--text)]">{label}</span>
        {sublabel && <span className="ml-2 text-xs text-[var(--text-dim)]">{sublabel}</span>}
      </div>
    </div>
  );
}
