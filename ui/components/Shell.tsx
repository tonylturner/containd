"use client";

import * as React from "react";
import { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

type NavItem = { href: string; label: string };
type NavGroup = { label: string; items: NavItem[]; defaultCollapsed?: boolean };

const navGroups: NavGroup[] = [
  {
    label: "Favorites",
    items: [{ href: "/", label: "Dashboard" }],
    defaultCollapsed: false,
  },
  {
    label: "System",
    items: [
      { href: "/system/settings/", label: "System Settings" },
      { href: "/system/users/", label: "User Management" },
      { href: "/system/services/", label: "Services" },
    ],
    defaultCollapsed: true,
  },
  {
    label: "Config",
    items: [
      { href: "/zones/", label: "Zones" },
      { href: "/interfaces/", label: "Interfaces" },
      { href: "/firewall/", label: "Firewall Rules" },
      { href: "/ics/", label: "ICS Policy" },
      { href: "/ids/", label: "IDS Rules" },
      { href: "/assets/", label: "Assets" },
      { href: "/proxies/", label: "Proxies" },
      { href: "/config/", label: "Config Lifecycle" },
    ],
    defaultCollapsed: true,
  },
  {
    label: "Operations",
    items: [{ href: "/dataplane/", label: "Dataplane" }],
    defaultCollapsed: true,
  },
  {
    label: "Monitoring",
    items: [
      { href: "/monitoring/", label: "Overview" },
      { href: "/topology/", label: "Topology" },
      { href: "/alerts/", label: "IDS Alerts" },
      { href: "/flows/", label: "Flows" },
      { href: "/events/", label: "Events" },
      { href: "/audit/", label: "Audit Log" },
    ],
    defaultCollapsed: true,
  },
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
  const pathname = usePathname() || "/";
  const [collapsed, setCollapsed] = React.useState<Record<string, boolean>>({});

  React.useEffect(() => {
    try {
      const raw = localStorage.getItem("containd.nav.collapsed");
      if (raw) {
        setCollapsed(JSON.parse(raw));
        return;
      }
    } catch {}
    const init: Record<string, boolean> = {};
    for (const g of navGroups) init[g.label] = g.defaultCollapsed ?? true;
    setCollapsed(init);
  }, []);

  function toggle(label: string) {
    setCollapsed((prev) => {
      const next = { ...prev, [label]: !prev[label] };
      try {
        localStorage.setItem("containd.nav.collapsed", JSON.stringify(next));
      } catch {}
      return next;
    });
  }

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 opacity-30">
        <div className="grid-overlay h-full w-full" />
      </div>

      <div className="relative flex min-h-screen">
        <aside className="w-64 shrink-0 border-r border-white/10 bg-black/30 backdrop-blur">
          <div className="flex items-center gap-3 px-5 py-5">
            <div className="h-2 w-2 rounded-full bg-mint" />
            <span className="text-lg font-semibold text-white">containd</span>
          </div>
          <nav className="px-2 pb-6 text-sm text-slate-200">
            {navGroups.map((group) => (
              <div key={group.label} className="mb-3">
                <button
                  type="button"
                  onClick={() => toggle(group.label)}
                  className="flex w-full items-center justify-between px-3 py-2 text-xs uppercase tracking-wide text-slate-400 hover:text-slate-200"
                >
                  <span>{group.label}</span>
                  <span>{collapsed[group.label] ? "▸" : "▾"}</span>
                </button>
                {!collapsed[group.label] &&
                  group.items.map((item) => {
                    const active =
                      item.href === "/"
                        ? pathname === "/"
                        : pathname.startsWith(item.href);
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        className={
                          active
                            ? "mb-1 block rounded-md bg-white/10 px-3 py-2 text-white"
                            : "mb-1 block rounded-md px-3 py-2 hover:bg-white/5"
                        }
                      >
                        {item.label}
                      </Link>
                    );
                  })}
              </div>
            ))}
          </nav>
        </aside>

        <main className="flex-1 px-6 py-8">
          <div className="mx-auto max-w-6xl">
            <div className="mb-6 flex items-center justify-between gap-4">
              <h1 className="text-2xl font-bold text-white">{title}</h1>
              {actions}
            </div>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
