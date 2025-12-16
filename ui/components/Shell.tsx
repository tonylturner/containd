"use client";

import * as React from "react";
import { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { api } from "../lib/api";

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

function buildNavGroups(isAdmin: boolean): NavGroup[] {
  const groups: NavGroup[] = [
    {
      label: "Favorites",
      items: [{ href: "/", label: "Dashboard" }],
      defaultCollapsed: false,
    },
    {
      label: "Config",
      items: [
        { href: "/zones/", label: "Zones" },
        { href: "/interfaces/", label: "Interfaces" },
        { href: "/routing/", label: "Routing" },
        { href: "/firewall/", label: "Firewall Rules" },
        { href: "/ics/", label: "ICS Policy" },
        { href: "/ids/", label: "IDS Rules" },
        { href: "/assets/", label: "Assets" },
        { href: "/dhcp/", label: "DHCP" },
        { href: "/proxies/", label: "Proxies" },
        { href: "/vpn/", label: "VPN" },
        { href: "/config/", label: "Config Lifecycle" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Operations",
      items: [
        { href: "/dataplane/", label: "Dataplane" },
        { href: "/diagnostics/", label: "Diagnostics" },
      ],
      defaultCollapsed: true,
    },
    {
      label: "Monitoring",
      items: [
        { href: "/monitoring/", label: "Overview" },
        { href: "/topology/", label: "Topology" },
        { href: "/alerts/", label: "IDS Alerts" },
        { href: "/sessions/", label: "Sessions" },
        { href: "/flows/", label: "Flows" },
        { href: "/events/", label: "Events" },
        { href: "/audit/", label: "Audit Log" },
      ],
      defaultCollapsed: true,
    },
  ];
  if (isAdmin) {
    groups.splice(1, 0, {
      label: "System",
      items: [
        { href: "/system/settings/", label: "System Settings" },
        { href: "/system/users/", label: "User Management" },
        { href: "/system/services/", label: "Services" },
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
  const [me, setMe] = React.useState<any>(null);
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [profileOpen, setProfileOpen] = React.useState(false);
  const [profileTab, setProfileTab] = React.useState<"profile" | "password">("profile");
  const redirectingRef = React.useRef(false);

  const isAdmin = (me?.role ?? "") === "admin";
  const navGroups = React.useMemo(() => buildNavGroups(isAdmin), [isAdmin]);

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
      // Some API calls can race a token refresh: one request may 401 while another (or the retry)
      // succeeds. Before bouncing the whole UI to /login, re-check auth once.
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
        // Actual navigation is centralized to avoid redirect storms.
        redirectToLogin("expired");
        return;
      }
      if (!data) {
        setAuthError("Unable to verify session (API unavailable).");
        setAuthChecked(false);
        return;
      }
      setMe(data);
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
        <aside className="relative w-64 shrink-0 border-r border-white/10 bg-black/30 backdrop-blur">
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

          {authChecked && me && (
            <div className="absolute bottom-0 left-0 right-0 border-t border-white/10 bg-black/40 p-3">
              <button
                type="button"
                onClick={() => setMenuOpen((v) => !v)}
                className="flex w-full items-center justify-between rounded-lg px-2 py-2 text-sm text-slate-200 hover:bg-white/5"
              >
                <div className="flex items-center gap-2">
                  <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-white/10">
                    <svg viewBox="0 0 24 24" className="h-4 w-4 text-slate-200" fill="currentColor" aria-hidden>
                      <path d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-3.33 0-8 1.67-8 5v1h16v-1c0-3.33-4.67-5-8-5Z" />
                    </svg>
                  </span>
                  <div className="text-left">
                    <div className="font-medium text-white">{me.username}</div>
                    <div className="text-xs text-slate-400">{me.role}</div>
                  </div>
                </div>
                <span className="text-xs text-slate-400">{menuOpen ? "▾" : "▸"}</span>
              </button>
              {menuOpen && (
                <div className="mt-2 grid gap-1 rounded-lg border border-white/10 bg-black/60 p-1 text-sm">
                  <button
                    type="button"
                    onClick={() => {
                      setProfileTab("profile");
                      setProfileOpen(true);
                      setMenuOpen(false);
                    }}
                    className="rounded-md px-3 py-2 text-left text-slate-200 hover:bg-white/10"
                  >
                    Profile
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setProfileTab("password");
                      setProfileOpen(true);
                      setMenuOpen(false);
                    }}
                    className="rounded-md px-3 py-2 text-left text-slate-200 hover:bg-white/10"
                  >
                    Reset password
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      await api.logout();
                      if (typeof window !== "undefined") window.location.href = "/login?reason=logout";
                    }}
                    className="rounded-md px-3 py-2 text-left text-slate-200 hover:bg-white/10"
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
          )}
        </aside>

        <main className="flex-1 px-6 py-8">
          <div className="mx-auto max-w-6xl">
            {!authChecked && (
              <div className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm text-slate-200">
                {authError ? (
                  <div className="flex items-center justify-between gap-3">
                    <div>{authError}</div>
                    <button
                      type="button"
                      onClick={() => {
                        if (typeof window !== "undefined") window.location.reload();
                      }}
                      className="rounded-lg bg-white/10 px-3 py-2 text-xs text-white hover:bg-white/20"
                    >
                      Reload
                    </button>
                  </div>
                ) : (
                  "Checking session…"
                )}
              </div>
            )}
            {authChecked && (
              <>
                <div className="mb-6 flex items-center justify-between gap-4">
                  <h1 className="text-2xl font-bold text-white">{title}</h1>
                  <div className="flex items-center gap-2">
                    {actions}
                    <a
                      href="/docs/"
                      target="_blank"
                      rel="noreferrer"
                      title="Help & documentation"
                      className="inline-flex items-center justify-center rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
                    >
                      <svg
                        viewBox="0 0 24 24"
                        className="h-4 w-4"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden
                      >
                        <path d="M12 18h.01" />
                        <path d="M9.09 9a3 3 0 1 1 5.82 1c0 2-3 2-3 4" />
                        <circle cx="12" cy="12" r="10" />
                      </svg>
                      <span className="sr-only">Help</span>
                    </a>
                  </div>
                </div>
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
          onClose={() => setProfileOpen(false)}
          onSaved={(u) => setMe(u)}
        />
      )}
    </div>
  );
}

function ProfileModal({
  me,
  initialTab,
  onClose,
  onSaved,
}: {
  me: any;
  initialTab: "profile" | "password";
  onClose: () => void;
  onSaved: (u: any) => void;
}) {
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
      // Focus the new password input after mount.
      setTimeout(() => passwordRef.current?.focus(), 50);
    }
  }, [initialTab]);

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
    if (!newPassword) {
      setError("New password required.");
      return;
    }
    if (!currentPassword) {
      setError("Current password required.");
      return;
    }
    setState("saving");
    const ok = await api.changeMyPassword(currentPassword, newPassword);
    if (!ok) {
      setState("error");
      setError("Failed to change password.");
      return;
    }
    setCurrentPassword("");
    setNewPassword("");
    setState("idle");
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="w-full max-w-lg rounded-2xl border border-white/10 bg-black/80 p-6 shadow-xl backdrop-blur">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Profile</h2>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md px-2 py-1 text-sm text-slate-300 hover:bg-white/10"
          >
            Close
          </button>
        </div>

        {error && (
          <div className="mb-3 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
            {error}
          </div>
        )}

        <div className="grid gap-2 md:grid-cols-2">
          <input
            value={firstName}
            onChange={(e) => setFirstName(e.target.value)}
            placeholder="first name"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <input
            value={lastName}
            onChange={(e) => setLastName(e.target.value)}
            placeholder="last name"
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="email"
            className="md:col-span-2 rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
          />
          <div className="md:col-span-2 text-xs text-slate-400">
            Role: {me.role} (roles are managed by admins)
          </div>
        </div>

        <div className="mt-3 flex items-center gap-2">
          <button
            type="button"
            onClick={saveProfile}
            className="rounded-lg bg-mint/20 px-3 py-1.5 text-sm text-mint hover:bg-mint/30"
          >
            Save profile
          </button>
          {state === "saving" && (
            <span className="text-xs text-slate-400">saving…</span>
          )}
        </div>

        <div className="mt-6 border-t border-white/10 pt-4">
          <h3 className="text-sm font-semibold text-white">Change password</h3>
          <div className="mt-2 grid gap-2">
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="current password"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="new password"
              ref={passwordRef}
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <button
              type="button"
              onClick={changePassword}
              className="rounded-lg bg-white/10 px-3 py-2 text-sm text-white hover:bg-white/20"
            >
              Update password
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
