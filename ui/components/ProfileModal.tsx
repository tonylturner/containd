"use client";

import * as React from "react";
import Image from "next/image";

import { type MFAEnrollResponse, type User, api } from "../lib/api";
import { formatOptionalDate } from "./shell-nav";

export function ProfileModal({
  me,
  initialTab,
  forcePassword,
  forceMFA,
  onClose,
  onSaved,
  onPasswordChanged,
}: {
  me: User;
  initialTab: "profile" | "password" | "mfa";
  forcePassword?: boolean;
  forceMFA?: boolean;
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
  const [mfaEnabled, setMfaEnabled] = React.useState(!!me.mfaEnabled);
  const [mfaEnrollment, setMfaEnrollment] =
    React.useState<MFAEnrollResponse | null>(null);
  const [mfaCode, setMfaCode] = React.useState("");
  const [mfaDisablePassword, setMfaDisablePassword] = React.useState("");
  const [mfaDisableCode, setMfaDisableCode] = React.useState("");
  const [state, setState] = React.useState<"idle" | "saving" | "error">("idle");
  const [error, setError] = React.useState<string | null>(null);
  const passwordRef = React.useRef<HTMLInputElement | null>(null);
  const mustStayOpen = !!forcePassword || !!forceMFA;
  const mfaRequired = !!me.mfaRequired;
  const mfaGraceDisplay = formatOptionalDate(me.mfaGraceUntil);

  React.useEffect(() => {
    setMfaEnabled(!!me.mfaEnabled);
  }, [me.mfaEnabled]);

  React.useEffect(() => {
    if (initialTab === "password") {
      setTimeout(() => passwordRef.current?.focus(), 50);
    }
  }, [initialTab]);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !mustStayOpen) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mustStayOpen, onClose]);

  async function saveProfile() {
    setError(null);
    setState("saving");
    const updated = await api.updateMe({ firstName, lastName, email });
    if (!updated.ok) {
      setState("error");
      setError(updated.error || "Failed to save profile.");
      return;
    }
    onSaved(updated.data);
    setState("idle");
  }

  async function changePassword() {
    setError(null);
    if (!currentPassword) {
      setError("Current password required.");
      return;
    }
    if (!newPassword) {
      setError("New password required.");
      return;
    }
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    setState("saving");
    const ok = await api.changeMyPassword(currentPassword, newPassword);
    if (!ok.ok) {
      setState("error");
      setError(
        ok.error || "Failed to change password. Check your current password.",
      );
      return;
    }
    setCurrentPassword("");
    setNewPassword("");
    setState("idle");
    onPasswordChanged?.();
    onClose();
  }

  async function startMFAEnrollment() {
    setError(null);
    setState("saving");
    const res = await api.startMFAEnrollment();
    if (!res.ok) {
      setState("error");
      setError(res.error || "Failed to start MFA setup.");
      return;
    }
    setMfaEnrollment(res.data);
    setMfaCode("");
    setState("idle");
  }

  async function enableMFA() {
    if (!mfaEnrollment) return;
    setError(null);
    if (!mfaCode.trim()) {
      setError("Authentication code required.");
      return;
    }
    setState("saving");
    const res = await api.enableMFA(mfaEnrollment.challengeToken, mfaCode);
    if (!res.ok) {
      setState("error");
      setError(res.error || "Failed to enable MFA.");
      return;
    }
    setMfaEnabled(true);
    setMfaEnrollment(null);
    setMfaCode("");
    setState("idle");
    onSaved({ ...me, mfaEnabled: true, mfaGraceUntil: undefined });
  }

  async function disableMFA() {
    setError(null);
    if (!mfaDisablePassword) {
      setError("Current password required.");
      return;
    }
    if (!mfaDisableCode.trim()) {
      setError("Authentication code required.");
      return;
    }
    setState("saving");
    const res = await api.disableMFA(mfaDisablePassword, mfaDisableCode);
    if (!res.ok) {
      setState("error");
      setError(res.error || "Failed to disable MFA.");
      return;
    }
    setMfaEnabled(false);
    setMfaEnrollment(null);
    setMfaCode("");
    setMfaDisablePassword("");
    setMfaDisableCode("");
    setState("idle");
    onSaved({ ...me, mfaEnabled: false, mfaGraceUntil: undefined });
  }

  const inputClass =
    "w-full rounded-lg border border-white/[0.08] bg-black/30 px-3 py-2 text-sm text-white placeholder:text-slate-500 transition-ui focus:border-blue-500/40 focus-visible:shadow-focus-ring outline-none";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 animate-fade-in"
      role="dialog"
      aria-labelledby="profile-modal-title"
    >
      <div className="w-full max-w-lg rounded-xl border border-white/[0.08] bg-surface-raised p-6 shadow-card-lg animate-slide-down">
        <div className="mb-4 flex items-center justify-between">
          <h2
            id="profile-modal-title"
            className="text-base font-semibold text-white"
          >
            Account
          </h2>
          {!mustStayOpen && (
            <button
              type="button"
              onClick={onClose}
              className="rounded-md p-1 text-slate-400 transition-ui hover:bg-white/[0.06] hover:text-white"
            >
              <svg
                viewBox="0 0 24 24"
                className="h-4 w-4"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {forcePassword && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-400">
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
            You must change the default password before continuing.
          </div>
        )}

        {forceMFA && !forcePassword && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-300">
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
            Your MFA grace period has expired. Set up MFA to regain full access.
          </div>
        )}

        {error && (
          <div className="mb-3 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            {error}
          </div>
        )}

        <div className="mb-4 flex gap-1 rounded-lg bg-white/[0.04] p-1">
          <button
            type="button"
            onClick={() => setTab("profile")}
            disabled={forcePassword || forceMFA}
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
          {!forcePassword && (
            <button
              type="button"
              onClick={() => setTab("mfa")}
              className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-ui ${tab === "mfa" ? "bg-white/[0.08] text-white" : "text-slate-400 hover:text-slate-200"}`}
            >
              MFA
            </button>
          )}
        </div>

        {tab === "profile" && (
          <div>
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label
                  htmlFor="profile-firstName"
                  className="mb-1 block text-xs font-medium text-slate-400"
                >
                  First name
                </label>
                <input
                  id="profile-firstName"
                  value={firstName}
                  onChange={(e) => setFirstName(e.target.value)}
                  placeholder="First name"
                  className={inputClass}
                />
              </div>
              <div>
                <label
                  htmlFor="profile-lastName"
                  className="mb-1 block text-xs font-medium text-slate-400"
                >
                  Last name
                </label>
                <input
                  id="profile-lastName"
                  value={lastName}
                  onChange={(e) => setLastName(e.target.value)}
                  placeholder="Last name"
                  className={inputClass}
                />
              </div>
              <div className="md:col-span-2">
                <label
                  htmlFor="profile-email"
                  className="mb-1 block text-xs font-medium text-slate-400"
                >
                  Email
                </label>
                <input
                  id="profile-email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="email@example.com"
                  type="email"
                  className={inputClass}
                />
              </div>
            </div>
            <div className="mt-2 text-xs text-slate-500">
              Role: {me.role} (managed by admins)
            </div>
            <div className="mt-4 flex items-center gap-3">
              <button
                type="button"
                onClick={saveProfile}
                disabled={state === "saving"}
                className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-amber-500 disabled:opacity-50"
              >
                {state === "saving" ? "Saving..." : "Save profile"}
              </button>
            </div>
          </div>
        )}

        {tab === "password" && (
          <div className="grid gap-3">
            <div>
              <label
                htmlFor="profile-current-pw"
                className="mb-1 block text-xs font-medium text-slate-400"
              >
                Current password
              </label>
              <input
                id="profile-current-pw"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Current password"
                autoComplete="current-password"
                className={inputClass}
              />
            </div>
            <div>
              <label
                htmlFor="profile-new-pw"
                className="mb-1 block text-xs font-medium text-slate-400"
              >
                New password
              </label>
              <input
                id="profile-new-pw"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New password (min 8 chars)"
                autoComplete="new-password"
                ref={passwordRef}
                className={inputClass}
              />
            </div>
            <button
              type="button"
              onClick={changePassword}
              disabled={state === "saving"}
              className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-amber-500 disabled:opacity-50"
            >
              {state === "saving" ? "Updating..." : "Update password"}
            </button>
          </div>
        )}

        {tab === "mfa" && !forcePassword && (
          <div className="grid gap-4">
            <div className="rounded-lg border border-white/[0.08] bg-black/20 px-3 py-3 text-sm text-slate-300">
              <div className="font-medium text-white">
                Authenticator app MFA
              </div>
              <div className="mt-1 text-xs text-slate-400">
                {mfaRequired
                  ? "This account is required to use TOTP-based MFA. SMS is intentionally not supported."
                  : "Optional TOTP-based MFA for local accounts. Recommended for admin and instructor accounts. SMS is intentionally not supported."}
              </div>
            </div>

            <div className="rounded-lg border border-white/[0.08] bg-black/20 px-3 py-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-white">Status</div>
                  <div className="mt-1 text-xs text-slate-400">
                    {mfaEnabled
                      ? mfaRequired
                        ? "Enabled and required for this account."
                        : "Enabled for this account."
                      : mfaRequired
                        ? mfaGraceDisplay
                          ? `Required for this account. Grace ends on ${mfaGraceDisplay}.`
                          : "Required for this account."
                        : "Disabled for this account."}
                  </div>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-2">
                  <span
                    className={`rounded-full px-2 py-1 text-[11px] ${mfaEnabled ? "bg-emerald-500/10 text-emerald-400" : "bg-white/[0.06] text-slate-300"}`}
                  >
                    {mfaEnabled ? "Enabled" : "Disabled"}
                  </span>
                  {mfaRequired && (
                    <span className="rounded-full bg-amber-500/10 px-2 py-1 text-[11px] text-amber-300">
                      Required
                    </span>
                  )}
                </div>
              </div>
            </div>

            {!mfaEnabled && !mfaEnrollment && (
              <div className="grid gap-3">
                <div className="text-xs text-slate-400">
                  Start setup to scan a QR code in Google Authenticator,
                  Microsoft Authenticator, or another TOTP-compatible app.
                </div>
                <button
                  type="button"
                  onClick={startMFAEnrollment}
                  disabled={state === "saving"}
                  className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-amber-500 disabled:opacity-50"
                >
                  {state === "saving" ? "Preparing..." : "Set up MFA"}
                </button>
              </div>
            )}

            {!mfaEnabled && mfaEnrollment && (
              <div className="grid gap-4">
                <div className="grid gap-4 md:grid-cols-[220px,1fr]">
                  <div className="rounded-lg border border-white/[0.08] bg-white p-2">
                    <Image
                      src={mfaEnrollment.qrDataURL}
                      alt="MFA enrollment QR code"
                      width={220}
                      height={220}
                      unoptimized
                      className="h-[220px] w-[220px]"
                    />
                  </div>
                  <div className="grid gap-3">
                    <div>
                      <div className="text-xs font-medium uppercase tracking-wide text-slate-400">
                        Manual entry secret
                      </div>
                      <div className="mt-1 rounded-md border border-white/[0.08] bg-black/20 px-3 py-2 font-mono text-sm text-white break-all">
                        {mfaEnrollment.secret}
                      </div>
                    </div>
                    <div>
                      <label
                        htmlFor="profile-mfa-code"
                        className="mb-1 block text-xs font-medium text-slate-400"
                      >
                        Enter the 6-digit code from your app
                      </label>
                      <input
                        id="profile-mfa-code"
                        value={mfaCode}
                        onChange={(e) => setMfaCode(e.target.value)}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="123456"
                        className={inputClass}
                      />
                    </div>
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        onClick={enableMFA}
                        disabled={state === "saving"}
                        className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-amber-500 disabled:opacity-50"
                      >
                        {state === "saving" ? "Enabling..." : "Enable MFA"}
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setMfaEnrollment(null);
                          setMfaCode("");
                          setError(null);
                          setState("idle");
                        }}
                        className="rounded-lg border border-white/[0.08] px-4 py-2 text-sm text-white transition-ui hover:bg-white/[0.06]"
                      >
                        Cancel setup
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {mfaEnabled && !mfaRequired && (
              <div className="grid gap-3">
                <div className="text-xs text-slate-400">
                  Disabling MFA requires your current password and a current
                  authenticator code.
                </div>
                <div>
                  <label
                    htmlFor="profile-mfa-disable-password"
                    className="mb-1 block text-xs font-medium text-slate-400"
                  >
                    Current password
                  </label>
                  <input
                    id="profile-mfa-disable-password"
                    type="password"
                    value={mfaDisablePassword}
                    onChange={(e) => setMfaDisablePassword(e.target.value)}
                    autoComplete="current-password"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label
                    htmlFor="profile-mfa-disable-code"
                    className="mb-1 block text-xs font-medium text-slate-400"
                  >
                    Authentication code
                  </label>
                  <input
                    id="profile-mfa-disable-code"
                    value={mfaDisableCode}
                    onChange={(e) => setMfaDisableCode(e.target.value)}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="123456"
                    className={inputClass}
                  />
                </div>
                <button
                  type="button"
                  onClick={disableMFA}
                  disabled={state === "saving"}
                  className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-ui hover:bg-red-500 disabled:opacity-50"
                >
                  {state === "saving" ? "Disabling..." : "Disable MFA"}
                </button>
              </div>
            )}

            {mfaEnabled && mfaRequired && (
              <div className="text-xs text-slate-400">
                MFA is required for this account. Contact an administrator if
                you need the requirement cleared or your MFA device reset.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
