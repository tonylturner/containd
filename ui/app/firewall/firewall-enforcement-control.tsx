"use client";

import { useState } from "react";
import Link from "next/link";
import { ConfirmDialog, useConfirm } from "../../components/ConfirmDialog";
import { isAdmin, type DataPlaneConfig, type EnforcementHealth } from "../../lib/api";
import type { ConfigWriteResult } from "../../lib/config-boundary";
import { revisionError } from "../../lib/config-revision";
import type { DefaultAction } from "./firewall-default-row";

export function FirewallEnforcementControl({ config, defaultAction, health, available, revision, onStage }: {
  config: DataPlaneConfig;
  defaultAction: DefaultAction;
  health: EnforcementHealth | undefined;
  available: boolean;
  revision: string;
  onStage: (next: boolean, revision: string) => Promise<ConfigWriteResult<DataPlaneConfig>>;
}) {
  const confirm = useConfirm();
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<{ revision: string; warning?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!isAdmin()) return null;
  // The API omits false booleans. A failed read is not an omitted field.
  const known = available && (config.enforcement === undefined || typeof config.enforcement === "boolean");
  const enabled = config.enforcement === true;
  const runtime = health?.state === "disabled" ? false
    : health?.state === "enforcing" || health?.state === "degraded" ? true : undefined;
  const staged = known && runtime !== undefined && runtime !== enabled;
  const latestSave = known && saved?.revision === revision;
  const acknowledged = latestSave && runtime === undefined;
  const label = enabled ? "Disable enforcement" : "Enable enforcement";

  async function stage() {
    setSaving(true);
    setError(null);
    const result = await onStage(!enabled, revision);
    setSaving(false);
    if (!result.ok) { setError(revisionError(result)); return; }
    if (result.adopted) setSaved({ revision: result.revision!, warning: result.warning });
  }

  return (
    <div className="basis-full text-sm">
      {!known ? <p className="text-(--text-muted)">Candidate enforcement unknown — refresh successfully before changing it.</p>
        : staged || acknowledged ? (
          <p role="status" className="text-(--amber)">
            Enforcement {enabled ? "on" : "off"} is staged — Review and commit.{" "}
            <Link href="/config/?tab=diff" className="underline">Review changes</Link>
            {latestSave && saved?.warning && ` Warning: ${saved.warning}`}
          </p>
        ) : (
          <button type="button" disabled={saving}
            className="rounded-xs border bg-(--surface2) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
            onClick={() => confirm.open({
              title: `${label}?`, confirmLabel: label, variant: "warning",
              message: <div className="space-y-2">
                <p>{enabled
                  ? "On commit, the firewall stops applying rules and the installed ruleset is removed."
                  : <>On commit, the firewall applies rules. Traffic no enforcing rule decides gets the firewall Default action: <strong>{defaultAction}</strong>.</>}</p>
                <p>This stages only; it does not commit or apply. Review changes and use Commit-confirmed so you can recover if access is interrupted.</p>
              </div>,
              onConfirm: () => { void stage(); },
            })}>{saving ? "Staging..." : label}</button>
        )}
      {error && <p role="alert" className="mt-2 text-red-400">{error}</p>}
      <ConfirmDialog {...confirm.props} />
    </div>
  );
}
