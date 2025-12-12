"use client";

import Link from "next/link";

import { Shell } from "../../components/Shell";

export default function ForbiddenPage() {
  return (
    <Shell title="Access denied">
      <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
        <p className="text-sm text-slate-200">
          You don&apos;t have permission to view this page.
        </p>
        <div className="mt-4 flex flex-wrap gap-2">
          <Link
            href="/"
            className="rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-200 hover:bg-white/10"
          >
            Go to dashboard
          </Link>
          <Link
            href="/login/"
            className="rounded-lg bg-mint/20 px-3 py-2 text-sm text-mint hover:bg-mint/30"
          >
            Switch user
          </Link>
        </div>
      </div>
    </Shell>
  );
}

