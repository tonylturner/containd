 "use client";

import { ReactNode } from "react";

const navItems = [
  { href: "/zones/", label: "Zones" },
  { href: "/interfaces/", label: "Interfaces" },
  { href: "/firewall/", label: "Firewall" },
  { href: "/assets/", label: "Assets" },
  { href: "/dataplane/", label: "Dataplane" },
];

export function Shell({
  title,
  children,
  actions,
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 opacity-30">
        <div className="grid-overlay h-full w-full" />
      </div>
      <header className="relative border-b border-white/10 bg-black/20 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <a href="/" className="flex items-center gap-3">
            <div className="h-2 w-2 rounded-full bg-mint" />
            <span className="text-lg font-semibold text-white">containd</span>
          </a>
          <nav className="flex items-center gap-1 text-sm text-slate-200">
            {navItems.map((item) => (
              <a
                key={item.href}
                href={item.href}
                className="rounded-md px-3 py-1.5 hover:bg-white/10"
              >
                {item.label}
              </a>
            ))}
          </nav>
        </div>
      </header>

      <main className="relative mx-auto max-w-6xl px-6 py-10">
        <div className="mb-6 flex items-center justify-between gap-4">
          <h1 className="text-2xl font-bold text-white">{title}</h1>
          {actions}
        </div>
        {children}
      </main>
    </div>
  );
}

