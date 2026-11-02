import Link from "next/link";
import type { ReactNode } from "react";

const steps = [
  { href: "/zones/", label: "Zones" },
  { href: "/interfaces/", label: "Logical interfaces" },
  { href: "/routing/", label: "Connectivity" },
  { href: "/config/?tab=diff", label: "Review" },
];

/** Navigation only: visiting another setup step never stages or applies settings. */
export function NetworkSetup({ current, children }: { current: string; children?: ReactNode }) {
  return (
    <div className="mb-4 space-y-2">
      <nav aria-label="Network setup" className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm text-(--text)">
        <ol aria-label="Network setup steps" className="flex min-w-0 flex-wrap items-center gap-2">
          {steps.map((step, index) => <li key={step.href} className="flex items-center gap-2">
            {index > 0 && <span aria-hidden="true">→</span>}
            <Link href={step.href} aria-current={current === step.href ? "page" : undefined} className="whitespace-nowrap text-(--amber)">{step.label}</Link>
          </li>)}
        </ol>
        <Link href="/nat/" aria-current={current === "/nat/" ? "page" : undefined} className="rounded-xs border px-3 py-1 text-(--amber) transition-ui hover:bg-(--surface2)">NAT</Link>
      </nav>
      {children && <p className="text-xs text-(--text-muted)">{children}</p>}
    </div>
  );
}
