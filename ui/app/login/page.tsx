"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, clearLocalAuth, getLastAuthError } from "../../lib/api";

type State = "idle" | "logging_in" | "error";

export default function LoginPage() {
  return (
    <Suspense>
      <LoginInner />
    </Suspense>
  );
}

function LoginInner() {
  const params = useSearchParams();
  const paramsKey = params?.toString() ?? "";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [state, setState] = useState<State>("idle");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [detail, setDetail] = useState<string | null>(null);
  const [alreadyLoggedIn, setAlreadyLoggedIn] = useState(false);

  useEffect(() => {
    const sp = new URLSearchParams(paramsKey);
    const reason = (sp.get("reason") ?? "").toLowerCase();
    const shouldClearLocal = reason === "expired" || reason === "logout";
    if (reason === "expired") {
      setInfo("Session expired. Please log in again.");
    } else if (reason === "logout") {
      setInfo("You have been logged out.");
    } else {
      setInfo(null);
    }
    (async () => {
      // Clear local token/role so stale localStorage auth can't override a valid cookie session.
      if (shouldClearLocal) clearLocalAuth();
      const { status } = await api.meStatus();
      // Avoid redirect loops between "/" and "/login". If we're already authenticated,
      // show a "continue" prompt instead of bouncing.
      setAlreadyLoggedIn(status === 200);
      if (status !== 200) {
        setDetail(getLastAuthError());
      } else {
        setDetail(null);
      }
    })();
  }, [paramsKey]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setState("logging_in");
    const res = await api.login(username, password);
    if (!res) {
      setState("error");
      setError("Invalid username or password.");
      setTimeout(() => setState("idle"), 1500);
      return;
    }
    // Verify we can see an authenticated session before navigating away. This avoids a confusing
    // redirect loop if the browser blocks cookies; the API layer will fall back to a tab-scoped
    // bearer token, but if *that* fails too we surface a clear error.
    const me = await api.meStatus();
    if (me.status !== 200) {
      setState("error");
      setError(
        "Login succeeded but the session could not be verified. Check that your browser allows cookies for this site and that you're using the same host (e.g. localhost vs 127.0.0.1).",
      );
      setTimeout(() => setState("idle"), 2500);
      return;
    }
    if (typeof window !== "undefined") {
      const next = params?.get("next");
      window.location.href = next && next.startsWith("/") ? next : "/";
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--bg)] text-[var(--text)]">
      <div className="w-full max-w-md rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-8 shadow-card-lg">
        <div className="mb-6 flex items-center gap-3">
          <div className="h-2 w-2 rounded-full bg-amber-500" />
          <h1 className="text-xl font-semibold text-[var(--text)]">containd login</h1>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {error}
          </div>
        )}
        {info && (
          <div className="mb-4 rounded-lg border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)]">
            {info}
          </div>
        )}
        {detail && (
          <div className="mb-4 rounded-lg border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)]">
            Last auth error: <span className="font-mono">{detail}</span>
          </div>
        )}

        {alreadyLoggedIn && (
          <div className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-[var(--text)]">
            You are already logged in.
            <div className="mt-2">
              <button
                type="button"
                onClick={() => {
                  if (typeof window !== "undefined") window.location.href = "/";
                }}
                className="rounded-sm bg-[var(--amber)] px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        <form onSubmit={onSubmit} className="grid gap-4">
          <div>
            <label htmlFor="login-username" className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">
              Username
            </label>
            <input
              id="login-username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full input-industrial"
              autoComplete="username"
            />
          </div>
          <div>
            <label htmlFor="login-password" className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full input-industrial"
              autoComplete="current-password"
            />
          </div>
          <button
            type="submit"
            disabled={state === "logging_in"}
            className="mt-2 rounded-sm bg-[var(--amber)] px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
          >
            {state === "logging_in" ? "Logging in..." : "Login"}
          </button>
        </form>

        <p className="mt-4 text-xs text-[var(--text-muted)]">
          Default credentials on fresh installs: containd / containd.
        </p>
      </div>
    </div>
  );
}
