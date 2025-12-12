"use client";

import { Shell } from "../../../components/Shell";

export default function UsersPage() {
  return (
    <Shell title="User Management">
      <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
        <p className="text-sm text-slate-200">
          User management and RBAC are not implemented yet. Current auth is
          token-based via environment variables.
        </p>
        <pre className="mt-3 rounded-lg bg-black/40 p-3 text-xs text-slate-200">
CONTAIND_LAB_MODE=1{"\n"}
CONTAIND_ADMIN_TOKEN=&lt;secret&gt;{"\n"}
CONTAIND_AUDITOR_TOKEN=&lt;secret&gt;
        </pre>
      </div>
    </Shell>
  );
}

