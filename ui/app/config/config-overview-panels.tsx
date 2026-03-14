"use client";

import type { ConfigBackup } from "../../lib/api";

import { Card } from "../../components/Card";

export function ConfigBackupRecoveryCard({
  backupName,
  backups,
  canEdit,
  formatBytes,
  onBackupNameChange,
  onCreateBackup,
  onDeleteBackup,
  onDownloadBackup,
  onDownloadConfig,
  onRestoreConfig,
  onUploadFileChange,
}: {
  backupName: string;
  backups: ConfigBackup[];
  canEdit: boolean;
  formatBytes: (size: number) => string;
  onBackupNameChange: (value: string) => void;
  onCreateBackup: (redacted: boolean) => void;
  onDeleteBackup: (backup: ConfigBackup) => void;
  onDownloadBackup: (backup: ConfigBackup) => void;
  onDownloadConfig: (redacted: boolean) => void;
  onRestoreConfig: () => void;
  onUploadFileChange: (file: File | null) => void;
}) {
  return (
    <Card padding="lg">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
            Backup &amp; Restore
          </div>
          <h2 className="text-lg font-semibold text-[var(--text)]">Backup &amp; recovery</h2>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onDownloadConfig(true)}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
          >
            Download redacted
          </button>
          {canEdit && (
            <button
              onClick={() => onDownloadConfig(false)}
              className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
            >
              Download full
            </button>
          )}
        </div>
      </div>
      <div className="mt-4 grid gap-3 md:grid-cols-[1.2fr_1fr_auto]">
        <input
          type="file"
          accept=".json"
          onChange={(e) => onUploadFileChange(e.target.files?.[0] ?? null)}
          disabled={!canEdit}
          className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
        />
        <div className="text-xs text-[var(--text-muted)]">
          Restore replaces the live config. Use redacted backups for sharing.
        </div>
        {canEdit && (
          <button
            onClick={onRestoreConfig}
            className="rounded-sm bg-[var(--amber)] px-3 py-2 text-sm font-medium text-white hover:brightness-110 transition-ui"
          >
            Restore
          </button>
        )}
      </div>
      <div className="mt-4 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-4 shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-dim)]">
              Appliance backups
            </div>
            <div className="text-sm text-[var(--text)]">Store backups on the firewall.</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => onCreateBackup(true)}
              disabled={!canEdit}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-xs text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
            >
              Save redacted
            </button>
            {canEdit && (
              <button
                onClick={() => onCreateBackup(false)}
                className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-xs font-medium text-white hover:brightness-110 transition-ui"
              >
                Save full
              </button>
            )}
          </div>
        </div>
        <div className="mt-3 grid gap-2 md:grid-cols-[1fr_auto]">
          <input
            value={backupName}
            onChange={(e) => onBackupNameChange(e.target.value)}
            placeholder="Name this backup (optional)"
            disabled={!canEdit}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
          />
          <div className="text-xs text-[var(--text-muted)]">
            Backups are stored under the appliance data volume.
          </div>
        </div>
        <div className="mt-3 grid gap-2">
          {backups.length === 0 ? (
            <div className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text-muted)]">
              No backups saved yet.
            </div>
          ) : (
            backups.map((backup) => (
              <div
                key={backup.id}
                className="grid gap-2 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text)] md:grid-cols-[1fr_auto]"
              >
                <div>
                  <div className="font-semibold text-[var(--text)]">{backup.name}</div>
                  <div className="text-[11px] text-[var(--text-muted)]">
                    {new Date(backup.createdAt).toLocaleString()} · {formatBytes(backup.size)} ·{" "}
                    {backup.redacted ? "Redacted" : "Full"}
                    {backup.idsRuleCount ? ` · ${backup.idsRuleCount} IDS rules` : ""} · ID {backup.id.slice(0, 6)}
                  </div>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-2">
                  <button
                    onClick={() => onDownloadBackup(backup)}
                    className="rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
                  >
                    Download
                  </button>
                  {canEdit && (
                    <button
                      onClick={() => onDeleteBackup(backup)}
                      className="rounded-md bg-red-600/20 px-2 py-1 text-xs text-red-400 hover:bg-red-600/30 transition-ui"
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </Card>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2">
      <span className="text-[var(--text)]">{label}</span>
      <span className="text-[var(--text)]">{value}</span>
    </div>
  );
}

export function ConfigSummaryCard({
  zoneCount,
  ifaceCount,
  ruleCount,
  assetCount,
  objectCount,
  idsRuleCount,
  dpiMode,
}: {
  zoneCount: number;
  ifaceCount: number;
  ruleCount: number;
  assetCount: number;
  objectCount: number;
  idsRuleCount: number;
  dpiMode: string;
}) {
  return (
    <Card padding="lg">
      <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Config summary</div>
      <div className="mt-3 grid gap-3 text-sm">
        <Stat label="Zones" value={zoneCount} />
        <Stat label="Interfaces" value={ifaceCount} />
        <Stat label="Firewall rules" value={ruleCount} />
        <Stat label="Assets" value={assetCount} />
        <Stat label="Objects" value={objectCount} />
        <Stat label="IDS rules" value={idsRuleCount} />
        <div className="flex items-center justify-between rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-2">
          <span className="text-[var(--text)]">DPI mode</span>
          <span
            className={
              dpiMode === "enforce"
                ? "text-emerald-400"
                : dpiMode === "learn"
                  ? "text-amber-400"
                  : "text-[var(--text-muted)]"
            }
          >
            {dpiMode}
          </span>
        </div>
      </div>
      <div className="mt-4 text-xs text-[var(--text-muted)]">
        Typical workflow: define zones, bind interfaces, add policy, review changes, then commit.
      </div>
    </Card>
  );
}

export function IDSRulesCard({
  canEdit,
  idsRuleCount,
  onDownloadRules,
  onRestoreRules,
}: {
  canEdit: boolean;
  idsRuleCount: number;
  onDownloadRules: () => void;
  onRestoreRules: (file: File | null) => void;
}) {
  return (
    <Card padding="md">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">IDS Rules</div>
          <div className="text-sm text-[var(--text)]">
            IDS rules are stored separately from the config ({idsRuleCount} rules loaded).
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={onDownloadRules}
            className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
          >
            Download rules
          </button>
          {canEdit && (
            <label className="cursor-pointer rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui">
              Restore rules
              <input
                type="file"
                accept=".json"
                className="hidden"
                onChange={(e) => {
                  onRestoreRules(e.target.files?.[0] ?? null);
                  e.target.value = "";
                }}
              />
            </label>
          )}
        </div>
      </div>
    </Card>
  );
}

export function ConfigActionBar({
  canEdit,
  ttlSeconds,
  onTtlChange,
  onCommit,
  onCommitConfirmed,
  onConfirmCommit,
  onRollback,
}: {
  canEdit: boolean;
  ttlSeconds: string;
  onTtlChange: (value: string) => void;
  onCommit: () => void;
  onCommitConfirmed: () => void;
  onConfirmCommit: () => void;
  onRollback: () => void;
}) {
  return (
    <Card className="mt-6" padding="md">
      <div className="flex flex-wrap items-center gap-2">
        {canEdit && (
          <button
            onClick={onCommit}
            className="rounded-sm bg-[var(--amber)] px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
          >
            Commit
          </button>
        )}
        <div className="flex items-center gap-2">
          {canEdit && (
            <button
              onClick={onCommitConfirmed}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
            >
              Commit-confirmed
            </button>
          )}
          <input
            value={ttlSeconds}
            onChange={(e) => onTtlChange(e.target.value)}
            disabled={!canEdit}
            className="w-20 rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 outline-none"
          />
          <span className="text-xs text-[var(--text)]">seconds</span>
        </div>
        {canEdit && (
          <>
            <button
              onClick={onConfirmCommit}
              className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] px-3 py-1.5 text-sm text-[var(--text)] hover:bg-amber-500/[0.08] transition-ui"
            >
              Confirm
            </button>
            <button
              onClick={onRollback}
              className="rounded-sm bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui"
            >
              Rollback
            </button>
          </>
        )}
      </div>
    </Card>
  );
}
