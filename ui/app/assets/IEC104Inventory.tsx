"use client";

import { useEffect, useState, type ReactNode } from "react";
import { api, type IEC104Inventory as Inventory } from "../../lib/api";
import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { StatusBadge } from "../../components/StatusBadge";

function Seen({ value }: { value: string }) {
  return <time dateTime={value}>{new Date(value).toLocaleString()}</time>;
}

// Mount CA/point tables only when expanded, rather than building the entire
// capped inventory's DOM while the operator is viewing station summaries.
function Disclosure({ summary, children }: { summary: ReactNode; children: () => ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <details onToggle={(event) => setOpen(event.currentTarget.open)} className="border-t py-3">
      <summary className="cursor-pointer wrap-break-word text-sm text-(--text) focus-visible:outline-solid">{summary}</summary>
      {open && children()}
    </details>
  );
}

export function IEC104Inventory({ refreshKey }: { refreshKey: number }) {
  return <InventoryContent key={refreshKey} />;
}

function InventoryContent() {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "unavailable">("loading");

  useEffect(() => {
    let active = true;
    api.getIEC104Inventory().then(({ data }) => {
      if (!active) return;
      setInventory(data);
      setState(data ? "ready" : "unavailable");
    });
    return () => { active = false; };
  }, []);

  return (
    <Card title="Passive IEC 104 inventory" className="mt-6">
      <p className="mb-4 text-sm text-(--text)">
        Observed controlling clients and controlled servers. Separate from configured assets and the learner; never generates auto-ALLOW rules.
      </p>
      {state === "loading" && <p role="status" className="text-sm text-(--text)">Loading IEC 104 inventory…</p>}
      {state === "unavailable" && (
        <p role="status" className="rounded-xs border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">
          IEC 104 inventory unavailable — the engine could not be reached. Use Refresh to retry; this is not an empty inventory.
        </p>
      )}
      {state === "ready" && inventory && <>
        <p className="mb-3 text-sm text-(--text)">
          Limits: {inventory.limits.pairs} pairs · {inventory.limits.casPerPair} CAs per pair · {inventory.limits.pointsPerCA} points per CA.
          Least recently observed entries are evicted; idle entries expire after {inventory.limits.maxIdleSeconds / 3600} hours.
        </p>
        <div aria-label="Inventory overflow counters" className="mb-4 flex flex-wrap gap-2">
          {([
            ["Busy observations", inventory.overflow.observations], ["Pairs", inventory.overflow.pairs], ["CAs", inventory.overflow.cas],
            ["Points", inventory.overflow.points], ["Lost outcomes", inventory.overflow.outcomes],
            ["Legacy assets", inventory.overflow.assets], ["Legacy peers", inventory.overflow.peers],
            ["Legacy station addresses", inventory.overflow.stationAddresses],
          ] as const).map(([label, count]) => (
            <StatusBadge key={label} variant={count ? "warning" : "neutral"}>{label} overflow: {count}</StatusBadge>
          ))}
        </div>
        <p className="mb-4 text-xs text-(--text)">
          Overflow totals count truncated observations or capacity evictions since inventory clear or engine restart, not unique missing devices. Busy observations and lost outcomes include data dropped on inventory lock contention.
          Attempted counts decoded client command APDUs; accepted requires an allow decision and successful Accept verdicts for every carrying packet in inline enforce mode only. Monitor and non-inline capture never claim delivery. Lost outcomes also include delivery-ledger overflow. Counts cover retained history, not lifetime traffic.
        </p>
        {inventory.pairs.length === 0 && <EmptyState title="No IEC 104 stations observed" description="Stations and points appear here when the engine supplies decoded IEC 104 observations." />}
        {inventory.pairs.map((pair) => (
          <Disclosure key={`${pair.controlling}-${pair.controlled}`} summary={<>
              <span className="font-mono">{pair.controlling}</span> (controlling client) → <span className="font-mono">{pair.controlled}</span> (controlled server)
              <span className="ml-3">{pair.attemptedCommands} attempted / {pair.acceptedCommands} accepted · {pair.cas.length} CAs</span>
            </>}>
            {() => <>
            <p className="my-3 text-xs text-(--text)">First seen: <Seen value={pair.firstSeen} /> · Last seen: <Seen value={pair.lastSeen} /></p>
            {pair.cas.map((ca) => (
              <Disclosure key={ca.ca} summary={<>
                  CA {ca.ca} · {ca.points.length} points · {ca.attemptedCommands} attempted / {ca.acceptedCommands} accepted
                </>}>
                {() => <>
                <p className="my-2 text-xs text-(--text)">First seen: <Seen value={ca.firstSeen} /> · Last seen: <Seen value={ca.lastSeen} /></p>
                <div className="overflow-x-auto">
                  <table aria-label={`CA ${ca.ca} observed points`} className="w-full text-left text-sm text-(--text)">
                    <thead><tr>{["IOA", "Type ID", "First seen", "Last seen"].map((label) => <th key={label} scope="col" className="px-3 py-2">{label}</th>)}</tr></thead>
                    <tbody>{ca.points.map((point) => (
                      <tr key={`${point.ioa}-${point.typeId}`} className="border-t table-row-hover">
                        <td className="px-3 py-2 font-mono">{point.ioa}</td><td className="px-3 py-2 font-mono">{point.typeId}</td>
                        <td className="whitespace-nowrap px-3 py-2"><Seen value={point.firstSeen} /></td><td className="whitespace-nowrap px-3 py-2"><Seen value={point.lastSeen} /></td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
                </>}
              </Disclosure>
            ))}
            </>}
          </Disclosure>
        ))}
      </>}
    </Card>
  );
}
