"use client";

import * as React from "react";

type EmptyStateProps = {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
};

export function EmptyState({ icon, title, description, action, className = "" }: EmptyStateProps) {
  return (
    <div className={`flex flex-col items-center justify-center rounded-sm border border-dashed border-amber-500/[0.15] bg-[var(--surface)] px-6 py-12 text-center ${className}`}>
      {icon && <div className="mb-3 text-[var(--text-dim)]">{icon}</div>}
      <h3 className="text-sm font-medium font-ui text-[var(--text)]">{title}</h3>
      {description && <p className="mt-1.5 max-w-sm text-xs text-[var(--text-dim)]">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
