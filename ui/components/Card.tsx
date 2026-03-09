"use client";

import * as React from "react";

type CardProps = {
  title?: string;
  titleRight?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  padding?: "sm" | "md" | "lg";
};

const paddingMap = {
  sm: "p-3",
  md: "p-4",
  lg: "p-5",
};

export function Card({ title, titleRight, children, className = "", padding = "md" }: CardProps) {
  return (
    <div className={`rounded-xl border border-white/[0.08] bg-white/[0.03] shadow-card ${paddingMap[padding]} ${className}`}>
      {title && (
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</h3>
          {titleRight}
        </div>
      )}
      {children}
    </div>
  );
}

/** Card variant for interactive/clickable items */
export function InteractiveCard({
  children,
  onClick,
  href,
  className = "",
}: {
  children: React.ReactNode;
  onClick?: () => void;
  href?: string;
  className?: string;
}) {
  const cls = `rounded-xl border border-white/[0.08] bg-white/[0.03] p-4 shadow-card transition-ui hover:bg-white/[0.06] hover:border-white/[0.12] cursor-pointer ${className}`;

  if (href) {
    return (
      <a href={href} className={cls}>
        {children}
      </a>
    );
  }

  return (
    <button type="button" onClick={onClick} className={`${cls} w-full text-left`}>
      {children}
    </button>
  );
}
