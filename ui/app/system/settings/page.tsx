"use client";

import { Shell } from "../../../components/Shell";

export default function SystemSettingsPage() {
  return (
    <Shell title="System Settings">
      <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
        <p className="text-sm text-slate-200">
          System settings UI is coming next. For now, use the CLI:
        </p>
        <pre className="mt-3 rounded-lg bg-black/40 p-3 text-xs text-slate-200">
show system{"\n"}
set system hostname &lt;name&gt;{"\n"}
set system mgmt listen &lt;addr&gt;{"\n"}
set system ssh listen &lt;addr&gt;{"\n"}
commit
        </pre>
      </div>
    </Shell>
  );
}
