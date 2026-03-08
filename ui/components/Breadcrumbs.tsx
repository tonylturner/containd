"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function Breadcrumbs() {
  const pathname = usePathname() || "/";

  // Split path into segments, filtering out empty strings.
  const segments = pathname.split("/").filter(Boolean);

  if (segments.length === 0) {
    return null; // Don't render breadcrumbs on the root/dashboard page.
  }

  // Build cumulative paths for each segment.
  const crumbs = segments.map((seg, i) => {
    const href = "/" + segments.slice(0, i + 1).join("/");
    const label = seg
      .replace(/-/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
    return { href, label };
  });

  return (
    <nav aria-label="Breadcrumb" className="mb-4 text-sm text-slate-400">
      <ol className="flex items-center gap-1">
        <li>
          <Link href="/" className="hover:text-white transition-colors">
            Home
          </Link>
        </li>
        {crumbs.map((crumb, i) => (
          <li key={crumb.href} className="flex items-center gap-1">
            <span className="text-slate-600">&gt;</span>
            {i === crumbs.length - 1 ? (
              <span className="text-slate-200">{crumb.label}</span>
            ) : (
              <Link href={crumb.href} className="hover:text-white transition-colors">
                {crumb.label}
              </Link>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
