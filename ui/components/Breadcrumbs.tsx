"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function Breadcrumbs() {
  const pathname = usePathname() || "/";

  const segments = pathname.split("/").filter(Boolean);

  if (segments.length === 0) {
    return null;
  }

  const crumbs = segments.map((seg, i) => {
    const href = "/" + segments.slice(0, i + 1).join("/");
    const label = seg
      .replace(/-/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return { href, label };
  });

  return (
    <nav aria-label="Breadcrumb" className="mb-4 font-mono text-[10px] tracking-wider text-[var(--text-dim)]">
      <ol className="flex items-center gap-1.5">
        <li>
          <Link href="/" className="transition-ui hover:text-[var(--amber)]">
            Home
          </Link>
        </li>
        {crumbs.map((crumb, i) => (
          <li key={crumb.href} className="flex items-center gap-1.5">
            <svg aria-hidden="true" viewBox="0 0 24 24" className="h-3 w-3 text-[var(--text-dim)]" fill="none" stroke="currentColor" strokeWidth={2}>
              <polyline points="9,6 15,12 9,18" />
            </svg>
            {i === crumbs.length - 1 ? (
              <span aria-current="page" className="text-[var(--text)]">{crumb.label}</span>
            ) : (
              <Link href={crumb.href} className="transition-ui hover:text-[var(--amber)]">
                {crumb.label}
              </Link>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
