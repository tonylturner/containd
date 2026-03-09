"use client";

import Link from "next/link";

import { Shell } from "../../components/Shell";

export default function ForbiddenPage() {
  return (
    <Shell title="Access denied">
      <div className="rounded-xl border border-white/[0.08] bg-white/[0.03] p-6 shadow-card backdrop-blur">
        <div className="flex items-start gap-4">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-red-500/30 bg-red-500/10">
            <svg
              viewBox="0 0 24 24"
              className="h-5 w-5 text-red-400"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden
            >
              <circle cx="12" cy="12" r="10" />
              <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
            </svg>
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">Permission denied</h2>
            <p className="mt-1 text-sm text-slate-300">
              You don&apos;t have permission to view this page. Contact your administrator if you believe this is an error.
            </p>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap gap-3">
          <Link
            href="/"
            className="rounded-lg border border-white/[0.08] bg-white/[0.04] px-3 py-2 text-sm text-slate-200 transition-ui hover:bg-white/[0.08]"
          >
            Go to dashboard
          </Link>
          <Link
            href="/login/"
            className="rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white transition-ui hover:bg-blue-500"
          >
            Switch user
          </Link>
        </div>
      </div>
    </Shell>
  );
}
