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
          <div className="text-xs uppercase tracking-[0.2em] text-(--text-muted)">
            Backup &amp; Restore
          </div>
          <h2 className="text-lg font-semibold text-(--text)">Backup &amp; recovery</h2>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onDownloadConfig(true)}
            className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Download redacted
          </button>
          {canEdit && (
            <button
              onClick={() => onDownloadConfig(false)}
              className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
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
          className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui outline-hidden"
        />
        <div className="text-xs text-(--text-muted)">
          Restore replaces the candidate config. Use redacted backups for sharing.
        </div>
        {canEdit && (
          <button
            onClick={onRestoreConfig}
            className="rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white hover:brightness-110 transition-ui"
          >
            Restore
          </button>
        )}
      </div>
      <div className="mt-4 rounded-xs border bg-(--surface) p-4 shadow-card">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-xs uppercase tracking-[0.2em] text-(--text-dim)">
              Appliance backups
            </div>
            <div className="text-sm text-(--text)">Store backups on the firewall.</div>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => onCreateBackup(true)}
              disabled={!canEdit}
              className="rounded-xs border bg-(--surface) px-3 py-1.5 text-xs text-(--text) transition-ui"
            >
              Save redacted
            </button>
            {canEdit && (
              <button
                onClick={() => onCreateBackup(false)}
                className="rounded-xs bg-(--amber) px-3 py-1.5 text-xs font-medium text-white hover:brightness-110 transition-ui"
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
            className="rounded-xs border bg-(--surface) px-3 py-2 text-sm text-(--text) transition-ui outline-hidden"
          />
          <div className="text-xs text-(--text-muted)">
            Backups are stored under the appliance data volume.
          </div>
        </div>
        <div className="mt-3 grid gap-2">
          {backups.length === 0 ? (
            <div className="rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text-muted)">
              No backups saved yet.
            </div>
          ) : (
            backups.map((backup) => (
              <div
                key={backup.id}
                className="grid gap-2 rounded-xs border bg-(--surface) px-3 py-2 text-xs text-(--text) md:grid-cols-[1fr_auto]"
              >
                <div>
                  <div className="font-semibold text-(--text)">{backup.name}</div>
                  <div className="text-[11px] text-(--text-muted)">
                    {new Date(backup.createdAt).toLocaleString()} · {formatBytes(backup.size)} ·{" "}
                    {backup.redacted ? "Redacted" : "Full"}
                    {backup.idsRuleCount ? ` · ${backup.idsRuleCount} IDS rules` : ""} · ID {backup.id.slice(0, 6)}
                  </div>
                </div>
                <div className="flex flex-wrap items-center justify-end gap-2">
                  <button
                    onClick={() => onDownloadBackup(backup)}
                    className="rounded-md border bg-(--surface) px-2 py-1 text-xs text-(--text) transition-ui"
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
    <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2">
      <span className="text-(--text)">{label}</span>
      <span className="text-(--text)">{value}</span>
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
      <div className="text-xs uppercase tracking-[0.2em] text-(--text-muted)">Config summary</div>
      <div className="mt-3 grid gap-3 text-sm">
        <Stat label="Zones" value={zoneCount} />
        <Stat label="Interfaces" value={ifaceCount} />
        <Stat label="Firewall rules" value={ruleCount} />
        <Stat label="Assets" value={assetCount} />
        <Stat label="Objects" value={objectCount} />
        <Stat label="IDS rules" value={idsRuleCount} />
        <div className="flex items-center justify-between rounded-xs border bg-(--surface) px-3 py-2">
          <span className="text-(--text)">DPI mode</span>
          {/* A mode is a preference, not proof of enforcement: never green. */}
          <span className={dpiMode === "enforce" || dpiMode === "learn" ? "" : "text-(--text-muted)"}>
            {dpiMode}
          </span>
        </div>
      </div>
      <div className="mt-4 text-xs text-(--text-muted)">
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
          <div className="text-xs uppercase tracking-[0.2em] text-(--text-muted)">IDS Rules</div>
          <div className="text-sm text-(--text)">
            Running IDS bank: {idsRuleCount} committed rules. Restores stage the candidate bank; commit promotes both.
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={onDownloadRules}
            className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
          >
            Download rule backup
          </button>
          {canEdit && (
            <label className="cursor-pointer rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui">
              Stage rule restore
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
            className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui"
          >
            Commit
          </button>
        )}
        <div className="flex items-center gap-2">
          {canEdit && (
            <button
              onClick={onCommitConfirmed}
              className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              Commit-confirmed
            </button>
          )}
          <input
            value={ttlSeconds}
            onChange={(e) => onTtlChange(e.target.value)}
            disabled={!canEdit}
            className="w-20 rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui outline-hidden"
          />
          <span className="text-xs text-(--text)">seconds</span>
        </div>
        {canEdit && (
          <>
            <button
              onClick={onConfirmCommit}
              className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui"
            >
              Confirm
            </button>
            <button
              onClick={onRollback}
              className="rounded-xs bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui"
            >
              Rollback
            </button>
          </>
        )}
      </div>
    </Card>
  );
}
