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
  const [username, setUsername] = useState("containd");
  const [password, setPassword] = useState("containd");
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
    <div className="flex min-h-screen items-center justify-center bg-black text-slate-100">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-white/5 p-8 shadow-lg backdrop-blur">
        <div className="mb-6 flex items-center gap-3">
          <div className="h-2 w-2 rounded-full bg-mint" />
          <h1 className="text-xl font-semibold text-white">containd login</h1>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
            {error}
          </div>
        )}
        {info && (
          <div className="mb-4 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200">
            {info}
          </div>
        )}
        {detail && (
          <div className="mb-4 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-300">
            Last auth error: <span className="font-mono">{detail}</span>
          </div>
        )}

        {alreadyLoggedIn && (
          <div className="mb-4 rounded-lg border border-mint/30 bg-mint/10 px-3 py-2 text-sm text-slate-100">
            You are already logged in.
            <div className="mt-2">
              <button
                type="button"
                onClick={() => {
                  if (typeof window !== "undefined") window.location.href = "/";
                }}
                className="rounded-lg bg-mint/20 px-3 py-2 text-sm text-mint hover:bg-mint/30"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        <form onSubmit={onSubmit} className="grid gap-3">
          <label className="text-xs uppercase tracking-wide text-slate-400">
            Username
          </label>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            autoComplete="username"
          />
          <label className="mt-2 text-xs uppercase tracking-wide text-slate-400">
            Password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            autoComplete="current-password"
          />
          <button
            type="submit"
            disabled={state === "logging_in"}
            className="mt-4 rounded-lg bg-mint/20 px-3 py-2 text-sm text-mint hover:bg-mint/30 disabled:opacity-60"
          >
            {state === "logging_in" ? "Logging in…" : "Login"}
          </button>
        </form>

        <p className="mt-4 text-xs text-slate-400">
          Default credentials on fresh installs: containd / containd.
        </p>
      </div>
    </div>
  );
}
