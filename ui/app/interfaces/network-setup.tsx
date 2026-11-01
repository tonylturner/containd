import Link from "next/link";
import { Fragment, type ReactNode } from "react";

const steps = [
  { href: "/zones/", label: "Zones" },
  { href: "/interfaces/", label: "Network devices" },
  { href: "/routing/", label: "Connectivity" },
  { href: "/config/", label: "Review" },
];

/** Navigation only: visiting another setup step never stages or applies settings. */
export function NetworkSetup({ current, children }: { current: string; children?: ReactNode }) {
  return (
    <nav aria-label="Network setup" className="mb-4 flex flex-wrap items-center gap-2 text-sm text-(--text)">
      {steps.map((step, index) => <Fragment key={step.href}>
        {index > 0 && <span aria-hidden="true">→</span>}
        <Link href={step.href} aria-current={current === step.href ? "page" : undefined} className="text-(--amber)">{step.label}</Link>
      </Fragment>)}
      <Link href="/nat/" aria-current={current === "/nat/" ? "page" : undefined} className="text-(--amber)">NAT</Link>
      {children && <span className="text-xs text-(--text-muted)">{children}</span>}
    </nav>
  );
}
