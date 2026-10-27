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
    <section aria-label={title} className={`card-industrial rounded-xs border bg-surface shadow-card ${paddingMap[padding]} ${className}`}>
      {title && (
        <div className="card-label mb-3 text-(--text-dim)">
          {title}
          {titleRight && <span className="ml-auto text-(--text-dim)">{titleRight}</span>}
        </div>
      )}
      {children}
    </section>
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
  const cls = `card-industrial rounded-xs border bg-surface p-4 shadow-card transition-ui cursor-pointer ${className}`;

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
