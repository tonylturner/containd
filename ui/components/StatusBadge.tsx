"use client";

import * as React from "react";

type BadgeVariant = "success" | "warning" | "error" | "info" | "neutral";

const variantClasses: Record<BadgeVariant, string> = {
  success: "bg-emerald-500/12 text-emerald-400 border-emerald-500/20",
  warning: "bg-amber-500/12 text-amber-400 border-amber-500/20",
  error: "bg-red-500/12 text-red-400 border-red-500/20",
  info: "bg-blue-500/12 text-blue-400 border-blue-500/20",
  neutral: "bg-white/5 text-slate-400 border-white/10",
};

type StatusBadgeProps = {
  variant: BadgeVariant;
  children: React.ReactNode;
  dot?: boolean;
  className?: string;
};

export function StatusBadge({ variant, children, dot, className = "" }: StatusBadgeProps) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${variantClasses[variant]} ${className}`}>
      {dot && <span className={`inline-block h-1.5 w-1.5 rounded-full ${
        variant === "success" ? "bg-emerald-400" :
        variant === "warning" ? "bg-amber-400" :
        variant === "error" ? "bg-red-400" :
        variant === "info" ? "bg-blue-400" :
        "bg-slate-400"
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
    healthy: "bg-emerald-400",
    degraded: "bg-amber-400",
    error: "bg-red-400",
    unknown: "bg-slate-500",
  };

  return (
    <div className="flex items-center gap-2.5">
      <span className={`h-2.5 w-2.5 rounded-full ${colors[status]}`} />
      <div>
        <span className="text-sm font-medium text-white">{label}</span>
        {sublabel && <span className="ml-2 text-xs text-slate-400">{sublabel}</span>}
      </div>
    </div>
  );
}
