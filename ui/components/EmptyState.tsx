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
    <div role="status" aria-label={title} className={`flex flex-col items-center justify-center rounded-xs border border-dashed bg-(--surface) px-6 py-12 text-center ${className}`}>
      {icon && <div aria-hidden="true" className="mb-3 text-(--text-dim)">{icon}</div>}
      <h3 className="text-sm font-medium font-ui text-(--text)">{title}</h3>
      {description && <p className="mt-1.5 max-w-sm text-xs text-(--text-dim)">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
