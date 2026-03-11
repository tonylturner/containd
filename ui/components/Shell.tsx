"use client";

import * as React from "react";
import { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { type User, api } from "../lib/api";
import { Breadcrumbs } from "./Breadcrumbs";
import { ConfigStatusBar } from "./ConfigStatusBar";

type NavItem = { href: string; label: string };
type NavGroup = { label: string; items: NavItem[]; defaultCollapsed?: boolean };

const REDIRECT_TRACE_KEY = "containd.auth.redirect_trace";

function appendRedirectTrace(entry: {
  ts: string;
  from: string;
  to: string;
  reason: string;
  stack?: string;
}) {
  if (typeof window === "undefined") return;
  try {
    const raw = sessionStorage.getItem(REDIRECT_TRACE_KEY);
    const arr = raw ? (JSON.parse(raw) as any[]) : [];
    arr.push(entry);
    while (arr.length > 20) arr.shift();
    sessionStorage.setItem(REDIRECT_TRACE_KEY, JSON.stringify(arr));
  } catch {
    // ignore
  }
}

/* ── Navigation icons (inline SVGs for zero-dep) ──────────── */
function IconShield() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
function IconNetwork() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="6" height="6" rx="1" /><rect x="16" y="2" width="6" height="6" rx="1" /><rect x="9" y="16" width="6" height="6" rx="1" />
      <path d="M5 8v3a3 3 0 003 3h8a3 3 0 003-3V8M12 14v2" />
    </svg>
  );
}
function IconMonitor() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
    </svg>
  );
}
function IconWrench() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z" />
    </svg>
  );
}
function IconServer() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" />
      <circle cx="6" cy="6" r="1" fill="currentColor" /><circle cx="6" cy="18" r="1" fill="currentColor" />
    </svg>
  );
}
function IconSettings() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  );
}

const NAV_ICONS: Record<string, () => React.ReactNode> = {
  "Policy & Rules": IconShield,
  "Network": IconNetwork,
  "Monitoring": IconMonitor,
  "Operations": IconWrench,
  "Services": IconServer,
  "System": IconSettings,
};

function docsHrefForPath(pathname: string): string {
  const mappings: Array<{ prefix: string; href: string }> = [
    { prefix: "/firewall/", href: "/docs/policy-model/" },
    { prefix: "/wizard/", href: "/docs/policy-model/" },
    { prefix: "/ics/", href: "/docs/ics-dpi/" },
    { prefix: "/ids/", href: "/docs/ids-rules/" },
    { prefix: "/templates/", href: "/docs/policy-model/" },
    { prefix: "/zones/", href: "/docs/policy-model/" },
    { prefix: "/interfaces/", href: "/docs/policy-model/" },
    { prefix: "/routing/", href: "/docs/config-format/" },
    { prefix: "/nat/", href: "/docs/policy-model/" },
    { prefix: "/dhcp/", href: "/docs/services/" },
    { prefix: "/vpn/", href: "/docs/services/" },
    { prefix: "/monitoring/", href: "/docs/api-reference/" },
    { prefix: "/topology/", href: "/docs/architecture/" },
    { prefix: "/flows/", href: "/docs/api-reference/" },
    { prefix: "/events/", href: "/docs/api-reference/" },
    { prefix: "/alerts/", href: "/docs/ids-rules/" },
    { prefix: "/assets/", href: "/docs/ics-dpi/" },
    { prefix: "/diagnostics/", href: "/docs/api-reference/" },
    { prefix: "/dataplane/", href: "/docs/dataplane/" },
    { prefix: "/pcap/", href: "/docs/ics-dpi/" },
    { prefix: "/system/services/", href: "/docs/services/" },
    { prefix: "/proxies/", href: "/docs/services/" },
    { prefix: "/config/", href: "/docs/config-format/" },
    { prefix: "/system/settings/", href: "/docs/api-reference/" },
    { prefix: "/system/users/", href: "/docs/api-reference/" },
  ];
  const match = mappings.find((entry) => pathname.startsWith(entry.prefix));
  return match?.href ?? "/docs/";
}

function buildNavGroups(isAdmin: boolean): NavGroup[] {
  const groups: NavGroup[] = [
    {
      label: "Policy & Rules",
      items: [
        { href: "/firewall/", label: "Firewall Rules" },
        { href: "/ics/", label: "ICS Rules" },
        { href: "/ids/", label: "IDS Rules" },
        { href: "/templates/", label: "Policy Templates" },
        { href: "/wizard/", label: "Policy Wizard" },
      ],
      defaultCollapsed: false,
    },
    {
      label: "Network",
      items: [
        { href: "/zones/", label: "Zones" },
        { href: "/interfaces/", label: "Interfaces" },
        { href: "/routing/", label: "Routing" },
        { href: "/nat/", label: "NAT" },
        { href: "/dhcp/", label: "DHCP" },
        { href: "/vpn/", label: "VPN" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Monitoring",
      items: [
        { href: "/monitoring/", label: "Telemetry" },
        { href: "/topology/", label: "Topology" },
        { href: "/flows/", label: "Active Flows" },
        { href: "/events/", label: "Events" },
        { href: "/alerts/", label: "IDS Alerts" },
        { href: "/assets/", label: "Assets" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Operations",
      items: [
        { href: "/diagnostics/", label: "Diagnostics" },
        { href: "/dataplane/", label: "PCAP Capture" },
        { href: "/pcap/", label: "PCAP Analysis" },
        { href: "/audit/", label: "Audit Log" },
        { href: "/sessions/", label: "Sessions" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Services",
      items: [
        { href: "/system/services/", label: "Service Status" },
        { href: "/system/services/dns/", label: "DNS" },
        { href: "/system/services/ntp/", label: "NTP" },
        { href: "/system/services/syslog/", label: "Syslog" },
        { href: "/proxies/", label: "Proxies" },
        { href: "/system/services/av/", label: "Antivirus" },
      ],
      defaultCollapsed: true,
    },
  ];
  if (isAdmin) {
    groups.push({
      label: "System",
      items: [
        { href: "/config/", label: "Configuration" },
        { href: "/system/settings/", label: "Settings" },
        { href: "/system/users/", label: "Users" },
      ],
      defaultCollapsed: true,
    });
  }
  return groups;
}

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
  const [authChecked, setAuthChecked] = React.useState(false);
  const [authError, setAuthError] = React.useState<string | null>(null);
  const [me, setMe] = React.useState<User | null>(null);
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [profileOpen, setProfileOpen] = React.useState(false);
  const [profileTab, setProfileTab] = React.useState<"profile" | "password">("profile");
  const redirectingRef = React.useRef(false);

  const isAdmin = (me?.role ?? "") === "admin";
  const navGroups = React.useMemo(() => buildNavGroups(isAdmin), [isAdmin]);
  const docsHref = React.useMemo(() => docsHrefForPath(pathname), [pathname]);

  // Auto-expand nav group containing the active page
  React.useEffect(() => {
    if (!pathname || pathname === "/") return;
    for (const g of navGroups) {
      if (g.items.some((item) => pathname.startsWith(item.href))) {
        setCollapsed((prev) => {
          if (prev[g.label] === false) return prev;
          return { ...prev, [g.label]: false };
        });
        break;
      }
    }
  }, [pathname, navGroups]);

  const redirectToLogin = React.useCallback(
    (reason: "expired" | "logout" | "forbidden" | "unauthenticated" = "unauthenticated") => {
      if (typeof window === "undefined") return;
      if (pathname.startsWith("/login")) return;
      if (redirectingRef.current) return;
      redirectingRef.current = true;
      const next = pathname.startsWith("/") ? pathname : "/";
      const url = `/login?reason=${encodeURIComponent(reason)}&next=${encodeURIComponent(next)}`;
      appendRedirectTrace({
        ts: new Date().toISOString(),
        from: pathname,
        to: url,
        reason,
        stack: new Error("redirectToLogin").stack || undefined,
      });
      window.location.href = url;
    },
    [pathname],
  );

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
  }, [navGroups]);

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const onExpired = async () => {
      try {
        const { status } = await api.meStatus();
        if (status === 200) return;
      } catch {
        // fall through
      }
      redirectToLogin("expired");
    };
    window.addEventListener("containd:auth:expired", onExpired as EventListener);
    return () => window.removeEventListener("containd:auth:expired", onExpired as EventListener);
  }, [redirectToLogin]);

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const onPasswordRequired = () => {
      setProfileTab("password");
      setProfileOpen(true);
      setMe((prev) => prev ? { ...prev, mustChangePassword: true } : prev);
    };
    window.addEventListener("containd:auth:password_change_required", onPasswordRequired as EventListener);
    return () => window.removeEventListener("containd:auth:password_change_required", onPasswordRequired as EventListener);
  }, []);

  React.useEffect(() => {
    if (pathname.startsWith("/login")) {
      setAuthChecked(true);
      setAuthError(null);
      return;
    }
    let canceled = false;
    setAuthChecked(false);
    setAuthError(null);
    api.meStatus().then(({ status, data }) => {
      if (canceled) return;
      if (status === 401) {
        redirectToLogin("expired");
        return;
      }
      if (!data) {
        setAuthError("Unable to verify session (API unavailable).");
        setAuthChecked(false);
        return;
      }
      setMe(data);
      if (data?.mustChangePassword) {
        setProfileTab("password");
        setProfileOpen(true);
      }
      if ((data?.role ?? "") !== "admin" && pathname.startsWith("/system/") && typeof window !== "undefined") {
        window.location.href = "/forbidden";
        return;
      }
      setAuthChecked(true);
    });
    return () => {
      canceled = true;
    };
  }, [pathname, redirectToLogin]);

  // Session keepalive: periodically touch the session so the JWT and cookie
  // stay fresh while the user is actively viewing any page.
  React.useEffect(() => {
    if (pathname.startsWith("/login")) return;
    const interval = setInterval(() => {
      api.meStatus().then(({ status }) => {
        if (status === 401) redirectToLogin("expired");
      });
    }, 4 * 60 * 1000); // every 4 minutes
    return () => clearInterval(interval);
  }, [pathname, redirectToLogin]);

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
    <div className="relative min-h-screen bg-[#080a0f] text-slate-100">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-black focus:px-4 focus:py-2 focus:text-white">
        Skip to main content
      </a>

      <div className="relative flex min-h-screen">
        {/* ── Sidebar ─────────────────────────────────────────── */}
        <aside aria-label="Sidebar" className="flex h-screen w-60 shrink-0 flex-col border-r border-amber-500/[0.15] bg-[#0a0d0a]/90 backdrop-blur-sm">
          {/* Brand */}
          <Link href="/" className="flex items-center gap-3 px-4 py-4 border-b border-amber-500/[0.15] transition-ui hover:bg-amber-500/[0.03]">
            <div className="flex h-8 w-8 items-center justify-center rounded-full border-2 border-amber-500/60" style={{ boxShadow: "0 0 12px rgba(245,158,11,0.15), inset 0 0 8px rgba(245,158,11,0.1)" }}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <circle cx="7" cy="7" r="3" fill="#f59e0b" />
                <circle cx="7" cy="7" r="6" stroke="#f59e0b" strokeWidth="1" strokeDasharray="3 2" />
              </svg>
            </div>
            <span className="text-sm font-bold tracking-[2px] uppercase text-amber-500">containd</span>
          </Link>

          {/* Navigation */}
          <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-2 py-3 pb-4 text-[13px]">
            {/* Dashboard link */}
            <div className="mb-1 px-1">
              <Link
                href="/"
                aria-current={pathname === "/" ? "page" : undefined}
                className={`flex items-center gap-2 rounded-lg px-2.5 py-1.5 transition-ui ${
                  pathname === "/"
                    ? "bg-amber-500/[0.12] text-amber-400 font-medium border-l-2 border-amber-500"
                    : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-200 border-l-2 border-transparent"
                }`}
              >
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" /><polyline points="9,22 9,12 15,12 15,22" />
                </svg>
                Dashboard
              </Link>
            </div>

            {navGroups.map((group) => {
              const isGroupActive = group.items.some(
                (item) => item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
              );
              const IconFn = NAV_ICONS[group.label];

              return (
                <div key={group.label} className="mt-3">
                  <button
                    type="button"
                    onClick={() => toggle(group.label)}
                    aria-expanded={!collapsed[group.label]}
                    className={`flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs font-medium uppercase tracking-wider transition-ui ${
                      isGroupActive && collapsed[group.label]
                        ? "text-amber-400/80 hover:text-amber-300"
                        : "text-slate-500 hover:text-slate-300 hover:bg-white/[0.03]"
                    }`}
                  >
                    {IconFn && <span aria-hidden="true" className="opacity-70">{IconFn()}</span>}
                    <span className="flex-1 text-left">{group.label}</span>
                    <svg
                      viewBox="0 0 24 24"
                      className={`h-3 w-3 transition-transform duration-200 ${collapsed[group.label] ? "" : "rotate-90"}`}
                      fill="none" stroke="currentColor" strokeWidth={2}
                    >
                      <polyline points="9,6 15,12 9,18" />
                    </svg>
                  </button>
                  {!collapsed[group.label] && (
                    <div className="mt-0.5 space-y-0.5 pl-2 animate-fade-in">
                      {group.items.map((item) => {
                        const active =
                          item.href === "/"
                            ? pathname === "/"
                            : pathname.startsWith(item.href);
                        return (
                          <Link
                            key={item.href}
                            href={item.href}
                            aria-current={active ? "page" : undefined}
                            className={`block rounded-lg px-2.5 py-1.5 transition-ui border-l-2 ${
                              active
                                ? "bg-amber-500/[0.08] text-amber-400 font-medium border-amber-500"
                                : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-200 border-transparent"
                            }`}
                          >
                            {item.label}
                          </Link>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </nav>

          {/* User section */}
          {authChecked && me && (
            <div className="shrink-0 border-t border-amber-500/[0.15] bg-black/20 p-2">
              <button
                type="button"
                onClick={() => setMenuOpen((v) => !v)}
                aria-expanded={menuOpen}
                aria-label="User menu"
                className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-ui hover:bg-white/[0.05]"
              >
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-full bg-amber-500/15 text-xs font-medium text-amber-400">
                  {(me.username?.[0] ?? "U").toUpperCase()}
                </span>
                <div className="min-w-0 flex-1 text-left">
                  <div className="truncate text-[13px] font-medium text-white">{me.username}</div>
                  <div className="text-xs text-slate-500">{me.role}</div>
                </div>
                <svg viewBox="0 0 24 24" className={`h-3 w-3 text-slate-500 transition-transform duration-200 ${menuOpen ? "rotate-180" : ""}`} fill="none" stroke="currentColor" strokeWidth={2}>
                  <polyline points="6,9 12,15 18,9" />
                </svg>
              </button>
              {menuOpen && (
                <div className="mt-1 rounded-lg border border-white/[0.08] bg-surface-raised p-1 animate-fade-in">
                  <button
                    type="button"
                    onClick={() => { setProfileTab("profile"); setProfileOpen(true); setMenuOpen(false); }}
                    className="flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-[13px] text-slate-300 transition-ui hover:bg-white/[0.06]"
                  >
                    Profile
                  </button>
                  <button
                    type="button"
                    onClick={() => { setProfileTab("password"); setProfileOpen(true); setMenuOpen(false); }}
                    className="flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-[13px] text-slate-300 transition-ui hover:bg-white/[0.06]"
                  >
                    Change password
                  </button>
                  <div className="my-1 border-t border-white/[0.06]" />
                  <button
                    type="button"
                    onClick={async () => { await api.logout(); if (typeof window !== "undefined") window.location.href = "/login?reason=logout"; }}
                    className="flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-[13px] text-red-400 transition-ui hover:bg-red-500/10"
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>
          )}
        </aside>

        {/* ── Main content ────────────────────────────────────── */}
        <main id="main-content" aria-label={title} className="flex-1 overflow-y-auto bg-[#080a0f] px-6 py-6">
          <div className="mx-auto max-w-6xl">
            {!authChecked && (
              <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] p-4 text-sm text-slate-300">
                {authError ? (
                  <div className="flex items-center justify-between gap-3">
                    <div>{authError}</div>
                    <button
                      type="button"
                      onClick={() => { if (typeof window !== "undefined") window.location.reload(); }}
                      className="rounded-lg bg-white/[0.08] px-3 py-1.5 text-xs text-white transition-ui hover:bg-white/[0.12]"
                    >
                      Reload
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-500 border-t-white" />
                    <span>Checking session...</span>
                  </div>
                )}
              </div>
            )}
            {authChecked && (
              <>
                {me?.labMode && (
                  <div className="mb-4 flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-sm text-amber-400">
                    <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2}>
                      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    <span><strong>Lab mode</strong> — Authentication is relaxed. Not suitable for production.</span>
                  </div>
                )}
                <ConfigStatusBar />
                <div className="mb-5 flex items-center justify-between gap-4">
                  <div>
                    <h1 className="text-lg font-semibold tracking-wide text-white">{title}</h1>
                  </div>
                  <div className="flex items-center gap-2">
                    {actions}
                    <a
                      href={docsHref}
                      target="_blank"
                      rel="noreferrer"
                      title="Help & documentation"
                      aria-label="Help & documentation"
                      className="inline-flex items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.04] p-2 text-slate-400 transition-ui hover:bg-white/[0.08] hover:text-slate-200"
                    >
                      <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                        <circle cx="12" cy="12" r="10" /><path d="M9.09 9a3 3 0 115.83 1c0 2-3 2-3 4" /><path d="M12 18h.01" />
                      </svg>
                    </a>
                  </div>
                </div>
                <Breadcrumbs />
                {children}
              </>
            )}
          </div>
        </main>
      </div>

      {profileOpen && me && (
        <ProfileModal
          me={me}
          initialTab={profileTab}
          forcePassword={!!me.mustChangePassword}
          onClose={() => { if (!me.mustChangePassword) setProfileOpen(false); }}
          onSaved={(u) => setMe(u)}
          onPasswordChanged={() => setMe((prev) => prev ? { ...prev, mustChangePassword: false } : prev)}
        />
      )}
    </div>
  );
}

function ProfileModal({
  me,
  initialTab,
  forcePassword,
  onClose,
  onSaved,
  onPasswordChanged,
}: {
  me: User;
  initialTab: "profile" | "password";
  forcePassword?: boolean;
  onClose: () => void;
  onSaved: (u: User) => void;
  onPasswordChanged?: () => void;
}) {
  const [tab, setTab] = React.useState(initialTab);
  const [firstName, setFirstName] = React.useState(me.firstName ?? "");
  const [lastName, setLastName] = React.useState(me.lastName ?? "");
  const [email, setEmail] = React.useState(me.email ?? "");
  const [currentPassword, setCurrentPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [state, setState] = React.useState<"idle" | "saving" | "error">("idle");
  const [error, setError] = React.useState<string | null>(null);
  const passwordRef = React.useRef<HTMLInputElement | null>(null);

  React.useEffect(() => {
    if (initialTab === "password") {
      setTimeout(() => passwordRef.current?.focus(), 50);
    }
  }, [initialTab]);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape" && !forcePassword) onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [forcePassword, onClose]);

  async function saveProfile() {
    setError(null);
    setState("saving");
    const updated = await api.updateMe({ firstName, lastName, email });
    if (!updated) {
      setState("error");
      setError("Failed to save profile.");
      return;
    }
    onSaved(updated);
    setState("idle");
  }

  async function changePassword() {
    setError(null);
    if (!currentPassword) { setError("Current password required."); return; }
    if (!newPassword) { setError("New password required."); return; }
    if (newPassword.length < 8) { setError("New password must be at least 8 characters."); return; }
    setState("saving");
    const ok = await api.changeMyPassword(currentPassword, newPassword);
    if (!ok) {
      setState("error");
      setError("Failed to change password. Check your current password.");
      return;
    }
    setCurrentPassword("");
    setNewPassword("");
    setState("idle");
    onPasswordChanged?.();
    onClose();
  }

  const inputClass = "w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 animate-fade-in" role="dialog" aria-labelledby="profile-modal-title">
      <div className="w-full max-w-lg rounded-xl border border-white/[0.08] bg-surface-raised p-6 shadow-card-lg animate-slide-down">
        <div className="mb-4 flex items-center justify-between">
          <h2 id="profile-modal-title" className="text-base font-semibold text-white">Account</h2>
          {!forcePassword && (
            <button type="button" onClick={onClose} className="rounded-md p-1 text-slate-400 transition-ui hover:bg-white/[0.06] hover:text-white">
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2}><path d="M18 6L6 18M6 6l12 12" /></svg>
            </button>
          )}
        </div>

        {forcePassword && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
            <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth={2}><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
            You must change the default password before continuing.
          </div>
        )}

        {error && (
          <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {error}
          </div>
        )}

        {/* Tabs */}
        <div className="mb-4 flex gap-1 rounded-lg bg-white/[0.04] p-1">
          <button
            type="button"
            onClick={() => setTab("profile")}
            disabled={forcePassword}
            className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-ui ${tab === "profile" ? "bg-white/[0.08] text-white" : "text-slate-400 hover:text-slate-200"} disabled:opacity-50`}
          >
            Profile
          </button>
          <button
            type="button"
            onClick={() => setTab("password")}
            className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-ui ${tab === "password" ? "bg-white/[0.08] text-white" : "text-slate-400 hover:text-slate-200"}`}
          >
            Password
          </button>
        </div>

        {tab === "profile" && (
          <div>
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label htmlFor="profile-firstName" className="mb-1 block text-xs font-medium text-slate-400">First name</label>
                <input id="profile-firstName" value={firstName} onChange={(e) => setFirstName(e.target.value)} placeholder="First name" className={inputClass} />
              </div>
              <div>
                <label htmlFor="profile-lastName" className="mb-1 block text-xs font-medium text-slate-400">Last name</label>
                <input id="profile-lastName" value={lastName} onChange={(e) => setLastName(e.target.value)} placeholder="Last name" className={inputClass} />
              </div>
              <div className="md:col-span-2">
                <label htmlFor="profile-email" className="mb-1 block text-xs font-medium text-slate-400">Email</label>
                <input id="profile-email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email@example.com" type="email" className={inputClass} />
              </div>
            </div>
            <div className="mt-2 text-xs text-slate-500">Role: {me.role} (managed by admins)</div>
            <div className="mt-4 flex items-center gap-3">
              <button type="button" onClick={saveProfile} disabled={state === "saving"} className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-amber-500 disabled:opacity-50">
                {state === "saving" ? "Saving..." : "Save profile"}
              </button>
            </div>
          </div>
        )}

        {tab === "password" && (
          <div className="grid gap-3">
            <div>
              <label htmlFor="profile-current-pw" className="mb-1 block text-xs font-medium text-slate-400">Current password</label>
              <input id="profile-current-pw" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" autoComplete="current-password" className={inputClass} />
            </div>
            <div>
              <label htmlFor="profile-new-pw" className="mb-1 block text-xs font-medium text-slate-400">New password</label>
              <input id="profile-new-pw" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (min 8 chars)" autoComplete="new-password" ref={passwordRef} className={inputClass} />
            </div>
            <button type="button" onClick={changePassword} disabled={state === "saving"} className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-amber-500 disabled:opacity-50">
              {state === "saving" ? "Updating..." : "Update password"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
