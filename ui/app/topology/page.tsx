"use client";

import { Shell } from "../../components/Shell";

export default function TopologyPage() {
  return (
    <Shell title="Topology">
      <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
        <p className="text-sm text-slate-200">
          Topology view is coming next. This placeholder will be replaced with a
          React Flow–based graph showing zones, interfaces, assets, and active
          flows.
        </p>
        <ul className="mt-4 list-disc space-y-1 pl-5 text-sm text-slate-300">
          <li>Zones as containers (wan/dmz/lan/mgmt).</li>
          <li>Interfaces attached to zones with live link state.</li>
          <li>Assets positioned per zone, tagged by type/criticality.</li>
          <li>Flow overlays from `/api/v1/flows`.</li>
        </ul>
      </div>
    </Shell>
  );
}

