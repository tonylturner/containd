"use client";

import * as React from "react";
import { ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { navigateToUI, uiNavigationPath, uiRoutePath } from "../lib/ui-navigation";
import { type User, api } from "../lib/api";
import { Breadcrumbs } from "./Breadcrumbs";
import { ConfigStatusBar } from "./ConfigStatusBar";
import { ShellRecoveryBanner } from "./ManagementRecoveryBanner";
import { ProfileModal } from "./ProfileModal";
import {
  buildNavGroups,
  docsHrefForPath,
  formatOptionalDate,
  isMFAGraceExpired,
  NAV_ICONS,
} from "./shell-nav";

// Shell owns high-level layout, session orchestration, and page chrome.
// Self-contained subflows such as nav metadata and profile/account UI belong
// in sibling modules instead of growing this file again.

const NAV_STORAGE_KEY = "containd.nav.collapsed";
function subscribeNavigation(notify: () => void) {
  window.addEventListener("storage", notify);
  window.addEventListener("containd:nav", notify);
  return () => {
    window.removeEventListener("storage", notify);
    window.removeEventListener("containd:nav", notify);
  };
}
function navigationSnapshot() {
  try { return localStorage.getItem(NAV_STORAGE_KEY) ?? "{}"; } catch { return "{}"; }
}

const REDIRECT_TRACE_KEY = "containd.auth.redirect_trace";

let verifiedSession: User | null = null;

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
  const routePath = uiRoutePath(pathname);
  const router = useRouter();
  const [initialPath] = React.useState(routePath);
  const storedNavigation = React.useSyncExternalStore(subscribeNavigation, navigationSnapshot, () => "{}");
  const [navigationChoice, setNavigationChoice] = React.useState<{ path: string; groups: Record<string, boolean> } | null>(null);
  const [authChecked, setAuthChecked] = React.useState(() => !!verifiedSession);
  const [authError, setAuthError] = React.useState<string | null>(null);
  const [me, setMe] = React.useState<User | null>(() => verifiedSession);
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [navigationPath, setNavigationPath] = React.useState<string | null>(null);
  const navigationOpen = navigationPath === pathname;
  const navigationToggleRef = React.useRef<HTMLButtonElement>(null);
  const [profileOpen, setProfileOpen] = React.useState(false);
  const [profileTab, setProfileTab] = React.useState<
    "profile" | "password" | "mfa"
  >("profile");
  const redirectingRef = React.useRef(false);

  const isAdmin = (me?.role ?? "") === "admin";
  const navGroups = React.useMemo(() => buildNavGroups(isAdmin).map((group) => ({
    ...group, items: group.items.map((item) => ({ ...item, href: uiRoutePath(item.href) })),
  })), [isAdmin]);
  const docsHref = React.useMemo(() => uiNavigationPath(docsHrefForPath(routePath), pathname), [routePath, pathname]);
  const pendingMFA = !!me?.mfaRequired && !me?.mfaEnabled;
  const forceMFA = pendingMFA && isMFAGraceExpired(me?.mfaGraceUntil);
  const mfaGraceDisplay = formatOptionalDate(me?.mfaGraceUntil);

  function closeNavigation() {
    setNavigationPath(null);
    navigationToggleRef.current?.focus();
  }

  const collapsed = React.useMemo(() => {
    if (navigationChoice?.path === routePath) return navigationChoice.groups;
    let saved: Record<string, boolean> = {};
    try { saved = JSON.parse(storedNavigation); } catch { /* Use group defaults for invalid storage. */ }
    return Object.fromEntries(navGroups.map((group) => [group.label,
      routePath !== initialPath && group.items.some((item) => routePath !== "/" && routePath.startsWith(item.href))
        ? false : saved?.[group.label] ?? group.defaultCollapsed ?? true,
    ]));
  }, [navGroups, routePath, initialPath, navigationChoice, storedNavigation]);

  const redirectToLogin = React.useCallback(
    (
      reason:
        | "expired"
        | "logout"
        | "forbidden"
        | "unauthenticated" = "unauthenticated",
    ) => {
      if (typeof window === "undefined") return;
      if (pathname.startsWith("/login") || pathname.startsWith("/containd/login")) return;
      if (redirectingRef.current) return;
      redirectingRef.current = true;
      const next = pathname.startsWith("/") ? pathname : "/";
      const login = `/login?reason=${encodeURIComponent(reason)}&next=${encodeURIComponent(next)}`;
      const url = uiNavigationPath(login, window.location.pathname);
      appendRedirectTrace({
        ts: new Date().toISOString(),
        from: pathname,
        to: url,
        reason,
        stack: new Error("redirectToLogin").stack || undefined,
      });
      navigateToUI(router, login);
    },
    [pathname, router],
  );

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
    window.addEventListener(
      "containd:auth:expired",
      onExpired as EventListener,
    );
    return () =>
      window.removeEventListener(
        "containd:auth:expired",
        onExpired as EventListener,
      );
  }, [redirectToLogin]);

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const onPasswordRequired = () => {
      setProfileTab("password");
      setProfileOpen(true);
      setMe((prev) => (prev ? { ...prev, mustChangePassword: true } : prev));
    };
    window.addEventListener(
      "containd:auth:password_change_required",
      onPasswordRequired as EventListener,
    );
    return () =>
      window.removeEventListener(
        "containd:auth:password_change_required",
        onPasswordRequired as EventListener,
      );
  }, []);

  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const onMFARequired = () => {
      setProfileTab("mfa");
      setProfileOpen(true);
    };
    window.addEventListener(
      "containd:auth:mfa_setup_required",
      onMFARequired as EventListener,
    );
    return () =>
      window.removeEventListener(
        "containd:auth:mfa_setup_required",
        onMFARequired as EventListener,
      );
  }, []);

  React.useEffect(() => {
    if (me) verifiedSession = me;
  }, [me]);

  React.useEffect(() => {
    if (pathname.startsWith("/login")) {
      return;
    }
    let canceled = false;
    api.meStatus().then(({ status, data }) => {
      if (canceled) return;
      if (status === 401) {
        verifiedSession = null;
        redirectToLogin("expired");
        return;
      }
      if (!data) {
        setAuthError("Unable to verify session (API unavailable).");
        return;
      }
      setAuthError(null);
      verifiedSession = data;
      setMe(data);
      if (data?.mustChangePassword) {
        setProfileTab("password");
        setProfileOpen(true);
      } else if (
        data?.mfaRequired &&
        !data?.mfaEnabled &&
        isMFAGraceExpired(data?.mfaGraceUntil)
      ) {
        setProfileTab("mfa");
        setProfileOpen(true);
      }
      if (
        (data?.role ?? "") !== "admin" &&
        pathname.startsWith("/system/") &&
        typeof window !== "undefined"
      ) {
        navigateToUI(router, "/forbidden");
        return;
      }
      setAuthChecked(true);
    });
    return () => {
      canceled = true;
    };
  }, [pathname, redirectToLogin, router]);

  // Session keepalive: periodically touch the session so the JWT and cookie
  // stay fresh while the user is actively viewing any page.
  React.useEffect(() => {
    if (pathname.startsWith("/login")) return;
    const interval = setInterval(
      () => {
        api.meStatus().then(({ status }) => {
          if (status === 401) redirectToLogin("expired");
        });
      },
      4 * 60 * 1000,
    ); // every 4 minutes
    return () => clearInterval(interval);
  }, [pathname, redirectToLogin]);

  function toggle(label: string) {
    const next = { ...collapsed, [label]: !collapsed[label] };
    setNavigationChoice({ path: routePath, groups: next });
    try {
      localStorage.setItem(NAV_STORAGE_KEY, JSON.stringify(next));
      window.dispatchEvent(new Event("containd:nav"));
    } catch { /* Navigation still works without persistent storage. */ }
  }

  return (
    <div
      className="relative min-h-screen bg-[#080a0f] text-slate-100"
      onKeyDown={(event) => {
        if (navigationOpen && event.key === "Escape") {
          event.preventDefault();
          closeNavigation();
        }
      }}
    >
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-black focus:px-4 focus:py-2 focus:text-white"
      >
        Skip to main content
      </a>

      <div className="flex h-14 items-center justify-between border-b bg-[#0a0d0a]/90 px-4 md:hidden">
        <Link href={uiNavigationPath("/", pathname)} className="text-sm font-bold tracking-[2px] uppercase">
          containd
        </Link>
        <button
          ref={navigationToggleRef}
          type="button"
          aria-label="Navigation"
          aria-controls="shell-sidebar"
          aria-expanded={navigationOpen}
          onClick={() => setNavigationPath(navigationOpen ? null : pathname)}
          className="inline-flex items-center gap-2 rounded-lg border border-white/8 bg-white/4 px-3 py-2 text-sm text-slate-200 transition-ui hover:bg-white/8 focus-visible:shadow-focus-ring"
        >
          <svg
            viewBox="0 0 24 24"
            className="h-4 w-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            strokeLinecap="round"
            aria-hidden="true"
          >
            {navigationOpen ? (
              <path d="m6 6 12 12M6 18 18 6" />
            ) : (
              <path d="M4 6h16M4 12h16M4 18h16" />
            )}
          </svg>
          {navigationOpen ? "Close" : "Menu"}
        </button>
      </div>

      <div className="relative flex min-h-[calc(100dvh-3.5rem)] flex-col md:min-h-screen md:flex-row">
        {/* ── Sidebar ─────────────────────────────────────────── */}
        <aside
          id="shell-sidebar"
          aria-label="Sidebar"
          onClick={(event) => {
            if (navigationOpen && (event.target as Element).closest("a")) {
              closeNavigation();
            }
          }}
          className={`${navigationOpen ? "flex" : "hidden"} h-[calc(100dvh-3.5rem)] w-full shrink-0 flex-col border-b bg-[#0a0d0a]/90 backdrop-blur-xs md:flex md:h-screen md:w-60 md:border-b-0 md:border-r`}
        >
          {/* Brand */}
          <Link
            href={uiNavigationPath("/", pathname)}
            className="hidden items-center gap-3 px-4 py-4 border-b transition-ui md:flex"
          >
            <div
              className="flex h-8 w-8 items-center justify-center rounded-full border-2"
              style={{
                boxShadow:
                  "0 0 12px rgba(245,158,11,0.15), inset 0 0 8px rgba(245,158,11,0.1)",
              }}
            >
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <circle cx="7" cy="7" r="3" fill="#f59e0b" />
                <circle
                  cx="7"
                  cy="7"
                  r="6"
                  stroke="#f59e0b"
                  strokeWidth="1"
                  strokeDasharray="3 2"
                />
              </svg>
            </div>
            <span className="text-sm font-bold tracking-[2px] uppercase">
              containd
            </span>
          </Link>

          {/* Navigation */}
          <nav
            aria-label="Main navigation"
            className="min-h-0 flex-1 overflow-y-auto px-2 py-3 pb-4 text-[13px]"
          >
            {/* Dashboard link */}
            <div className="mb-1 px-1">
              <Link
                href={uiNavigationPath("/", pathname)}
                aria-current={routePath === "/" ? "page" : undefined}
                className={`flex items-center gap-2 rounded-lg px-2.5 py-1.5 transition-ui ${
                  routePath === "/"
                    ? "font-medium border-l-2 "
                    : "text-slate-400 hover:bg-white/4 hover:text-slate-200 border-l-2 border-transparent"
                }`}
              >
                <svg
                  viewBox="0 0 24 24"
                  className="h-4 w-4"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={1.5}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
                  <polyline points="9,22 9,12 15,12 15,22" />
                </svg>
                Dashboard
              </Link>
            </div>

            {navGroups.map((group) => {
              const isGroupActive = group.items.some((item) =>
                item.href === "/"
                  ? routePath === "/"
                  : routePath.startsWith(item.href),
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
                        ? ""
                        : "text-slate-500 hover:text-slate-300 hover:bg-white/3"
                    }`}
                  >
                    {IconFn && (
                      <span aria-hidden="true" className="opacity-70">
                        {IconFn()}
                      </span>
                    )}
                    <span className="flex-1 text-left">{group.label}</span>
                    <svg
                      viewBox="0 0 24 24"
                      className={`h-3 w-3 transition-transform duration-200 ${collapsed[group.label] ? "" : "rotate-90"}`}
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={2}
                    >
                      <polyline points="9,6 15,12 9,18" />
                    </svg>
                  </button>
                  {!collapsed[group.label] && (
                    <div className="mt-0.5 space-y-0.5 pl-2 animate-fade-in">
                      {group.items.map((item) => {
                        const active =
                          item.href === "/"
                            ? routePath === "/"
                            : routePath.startsWith(item.href);
                        return (
                          <Link
                            key={item.href}
                            href={uiNavigationPath(item.href, pathname)}
                            aria-current={active ? "page" : undefined}
                            className={`block rounded-lg px-2.5 py-1.5 transition-ui border-l-2 ${
                              active
                                ? "font-medium "
                                : "text-slate-400 hover:bg-white/4 hover:text-slate-200 border-transparent"
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
            <div className="shrink-0 border-t bg-black/20 p-2">
              <button
                type="button"
                onClick={() => setMenuOpen((v) => !v)}
                aria-expanded={menuOpen}
                aria-label="User menu"
                className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-ui hover:bg-white/5"
              >
                <span className="inline-flex h-7 w-7 items-center justify-center rounded-full text-xs font-medium">
                  {(me.username?.[0] ?? "U").toUpperCase()}
                </span>
                <div className="min-w-0 flex-1 text-left">
                  <div className="truncate text-[13px] font-medium text-white">
                    {me.username}
                  </div>
                  <div className="text-xs text-slate-500">{me.role}</div>
                </div>
                <svg
                  viewBox="0 0 24 24"
                  className={`h-3 w-3 text-slate-500 transition-transform duration-200 ${menuOpen ? "rotate-180" : ""}`}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <polyline points="6,9 12,15 18,9" />
                </svg>
              </button>
              {menuOpen && (
                <div className="mt-1 rounded-lg border border-white/8 bg-surface-raised p-1 animate-fade-in">
                  <button
                    type="button"
                    onClick={() => {
                      setProfileTab("profile");
                      setProfileOpen(true);
                      setMenuOpen(false);
                    }}
                    className="flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-[13px] text-slate-300 transition-ui hover:bg-white/6"
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
                    className="flex w-full items-center gap-2 rounded-md px-3 py-1.5 text-[13px] text-slate-300 transition-ui hover:bg-white/6"
                  >
                    Change password
                  </button>
                  <div className="my-1 border-t border-white/6" />
                  <button
                    type="button"
                    onClick={async () => {
                      await api.logout();
                      verifiedSession = null;
                      if (typeof window !== "undefined")
                        navigateToUI(router, "/login?reason=logout");
                    }}
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
        <main
          id="main-content"
          aria-label={title}
          className="min-w-0 flex-1 overflow-auto bg-[#080a0f] px-4 py-6 md:px-6"
        >
          <div className="mx-auto max-w-6xl">
            {!authChecked && (
              <div className="rounded-xl border border-white/8 bg-white/3 p-4 text-sm text-slate-300">
                {authError ? (
                  <div className="flex items-center justify-between gap-3">
                    <div>{authError}</div>
                    <button
                      type="button"
                      onClick={() => {
                        if (typeof window !== "undefined")
                          window.location.reload();
                      }}
                      className="rounded-lg bg-white/8 px-3 py-1.5 text-xs text-white transition-ui hover:bg-white/12"
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
                  <div className="mb-4 flex items-center gap-2 rounded-xl border px-4 py-2.5 text-sm">
                    <svg
                      viewBox="0 0 24 24"
                      className="h-4 w-4 shrink-0"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth={2}
                    >
                      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
                      <line x1="12" y1="9" x2="12" y2="13" />
                      <line x1="12" y1="17" x2="12.01" y2="17" />
                    </svg>
                    <span>
                      <strong>Lab mode</strong> — Authentication is relaxed. Not
                      suitable for production.
                    </span>
                  </div>
                )}
                {pendingMFA && !forceMFA && (
                  <div className="mb-4 flex items-start justify-between gap-3 rounded-xl border px-4 py-3 text-sm">
                    <div>
                      <div className="font-medium">
                        MFA setup is required for this account
                      </div>
                      <div className="mt-1 text-xs">
                        You can still sign in without MFA during the grace
                        period, but you should complete setup soon.
                        {mfaGraceDisplay
                          ? ` Grace ends on ${mfaGraceDisplay}.`
                          : ""}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setProfileTab("mfa");
                        setProfileOpen(true);
                      }}
                      className="shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium transition-ui"
                    >
                      Set up MFA
                    </button>
                  </div>
                )}
                {forceMFA && (
                  <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
                    <div className="font-medium text-red-200">
                      MFA setup required before continuing
                    </div>
                    <div className="mt-1 text-xs text-red-200/90">
                      Your MFA grace period has expired. Complete authenticator
                      app setup to regain full access.
                    </div>
                  </div>
                )}
                <ShellRecoveryBanner />
                <ConfigStatusBar />
                <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
                  <div>
                    <h1 className="text-lg font-semibold tracking-wide text-white">
                      {title}
                    </h1>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    {actions}
                    <a
                      href={docsHref}
                      target="_blank"
                      rel="noreferrer"
                      title="Help & documentation"
                      aria-label="Help & documentation"
                      className="inline-flex items-center justify-center rounded-lg border border-white/8 bg-white/4 p-2 text-slate-400 transition-ui hover:bg-white/8 hover:text-slate-200"
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
                        <circle cx="12" cy="12" r="10" />
                        <path d="M9.09 9a3 3 0 115.83 1c0 2-3 2-3 4" />
                        <path d="M12 18h.01" />
                      </svg>
                    </a>
                  </div>
                </div>
                <Breadcrumbs />
                {forceMFA ? (
                  <div className="rounded-xl border border-white/8 bg-white/3 p-6 text-sm text-slate-300">
                    Only account and MFA setup actions are available until MFA
                    is enabled for this account.
                  </div>
                ) : (
                  children
                )}
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
          forceMFA={forceMFA}
          onClose={() => {
            if (!me.mustChangePassword && !forceMFA) setProfileOpen(false);
          }}
          onSaved={(u) => setMe(u)}
          onPasswordChanged={() =>
            setMe((prev) =>
              prev ? { ...prev, mustChangePassword: false } : prev,
            )
          }
        />
      )}
    </div>
  );
}
