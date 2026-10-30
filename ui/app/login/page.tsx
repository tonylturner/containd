"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { api, clearLocalAuth, getLastAuthError, type ApiFailure } from "../../lib/api";
import { withRetryTime } from "../../lib/utils";
import { navigateToUI } from "../../lib/ui-navigation";

type State = "idle" | "logging_in" | "verifying_mfa" | "error";

/**
 * A rate limit or factor lock says why and when to retry; any other refusal
 * keeps the generic text, which reveals nothing about the account.
 */
function loginFailure(failure: ApiFailure, generic: string): string {
  return failure.retryAfter === undefined ? generic : withRetryTime(failure.error, failure.retryAfter);
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginInner />
    </Suspense>
  );
}

function LoginInner() {
  const router = useRouter();
  const params = useSearchParams();
  const paramsKey = params?.toString() ?? "";
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [state, setState] = useState<State>("idle");
  const [error, setError] = useState<string | null>(null);
  const [loginInfo, setInfo] = useState<string | null>(null);
  const reason = (params.get("reason") ?? "").toLowerCase();
  const info = loginInfo ?? (reason === "expired" ? "Session expired. Please log in again."
    : reason === "logout" ? "You have been logged out." : null);
  const [detail, setDetail] = useState<string | null>(null);
  const [alreadyLoggedIn, setAlreadyLoggedIn] = useState(false);
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  useEffect(() => {
    const sp = new URLSearchParams(paramsKey);
    const reason = (sp.get("reason") ?? "").toLowerCase();
    const shouldClearLocal = reason === "expired" || reason === "logout";
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

  async function completeLoginRedirect() {
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
      navigateToUI(router, next ?? "/");
    }
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setState("logging_in");
    const result = await api.login(username, password);
    if (!result.ok) {
      setState("error");
      setError(loginFailure(result, "Invalid username or password."));
      setTimeout(() => setState("idle"), 1500);
      return;
    }
    const res = result.data;
    if ("mfaRequired" in res && res.mfaRequired) {
      setChallengeToken(res.mfaChallengeToken);
      setMfaCode("");
      setPassword("");
      setState("idle");
      setInfo(
        "Enter the 6-digit code from your authenticator app to finish signing in.",
      );
      return;
    }
    await completeLoginRedirect();
  }

  async function onVerifyMFA(e: React.FormEvent) {
    e.preventDefault();
    if (!challengeToken) return;
    setError(null);
    setState("verifying_mfa");
    const res = await api.verifyLoginMFA(challengeToken, mfaCode);
    if (!res.ok) {
      setState("error");
      setError(loginFailure(res, "Invalid authentication code."));
      setTimeout(() => setState("idle"), 1500);
      return;
    }
    await completeLoginRedirect();
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-(--bg) text-(--text)">
      <div className="w-full max-w-md rounded-xs border bg-(--surface) p-8 shadow-card-lg">
        <div className="mb-6 flex items-center gap-3">
          <div className="h-2 w-2 rounded-full" />
          <h1 className="text-xl font-semibold text-(--text)">
            containd login
          </h1>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {error}
          </div>
        )}
        {info && (
          <div className="mb-4 rounded-lg border bg-(--surface) px-3 py-2 text-sm text-(--text)">
            {info}
          </div>
        )}
        {detail && (
          <div className="mb-4 rounded-lg border bg-(--surface) px-3 py-2 text-xs text-(--text)">
            Last auth error: <span className="font-mono">{detail}</span>
          </div>
        )}

        {alreadyLoggedIn && (
          <div className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-(--text)">
            You are already logged in.
            <div className="mt-2">
              <button
                type="button"
                onClick={() => {
                  if (typeof window !== "undefined") navigateToUI(router, "/");
                }}
                className="rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {!challengeToken ? (
          <form onSubmit={onSubmit} className="grid gap-4">
            <div>
              <label
                htmlFor="login-username"
                className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-(--text-muted)"
              >
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
              <label
                htmlFor="login-password"
                className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-(--text-muted)"
              >
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
              className="mt-2 rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
            >
              {state === "logging_in" ? "Logging in..." : "Login"}
            </button>
          </form>
        ) : (
          <form onSubmit={onVerifyMFA} className="grid gap-4">
            <div className="rounded-lg border bg-(--surface) px-3 py-2 text-xs text-(--text-muted)">
              Password verified. Finish sign-in with the 6-digit code from your
              authenticator app.
            </div>
            <div>
              <label
                htmlFor="login-mfa-code"
                className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-(--text-muted)"
              >
                Authentication Code
              </label>
              <input
                id="login-mfa-code"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="w-full input-industrial"
                autoComplete="one-time-code"
                inputMode="numeric"
                placeholder="123456"
              />
            </div>
            <button
              type="submit"
              disabled={state === "verifying_mfa"}
              className="mt-2 rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
            >
              {state === "verifying_mfa" ? "Verifying..." : "Verify code"}
            </button>
            <button
              type="button"
              onClick={() => {
                setChallengeToken(null);
                setMfaCode("");
                setInfo(null);
                setError(null);
                setState("idle");
              }}
              className="rounded-xs border px-3 py-2 text-sm text-(--text) transition-ui"
            >
              Back
            </button>
          </form>
        )}

        <p className="mt-4 text-xs text-(--text-muted)">
          Default credentials on fresh installs: containd / containd.
        </p>
      </div>
    </div>
  );
}
