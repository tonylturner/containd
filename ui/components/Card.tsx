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
    <div className={`card-industrial rounded-sm border border-amber-500/[0.15] bg-[#0d110d] shadow-card ${paddingMap[padding]} ${className}`}>
      {title && (
        <div className="card-label mb-3 text-[var(--text-dim)]">
          {title}
          {titleRight && <span className="ml-auto text-[var(--text-dim)]">{titleRight}</span>}
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
  const cls = `card-industrial rounded-sm border border-amber-500/[0.15] bg-[#0d110d] p-4 shadow-card transition-ui hover:border-amber-500/30 cursor-pointer ${className}`;

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
