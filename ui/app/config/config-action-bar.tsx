import { useState } from "react";
import { Card } from "../../components/Card";
import { Disclosure } from "../../components/Disclosure";
import { factoryResetLoginGuidance } from "../../lib/recovery-guidance";
import type { DeploymentProfile } from "../../lib/api";

export function ConfigActionBar({
  canEdit,
  canCommit,
  canMutate,
  profile,
  labMode,
  showReview,
  pendingConfirm,
  ttlSeconds,
  onTtlChange,
  onCommit,
  onCommitConfirmed,
  onConfirmCommit,
  onRollback,
  onFactoryReset,
}: {
  canEdit: boolean;
  canCommit: boolean;
  canMutate: boolean;
  profile?: DeploymentProfile;
  labMode?: boolean;
  showReview: boolean;
  pendingConfirm: boolean;
  ttlSeconds: string;
  onTtlChange: (value: string) => void;
  onCommit: () => void;
  onCommitConfirmed: () => void;
  onConfirmCommit: () => void;
  onRollback: () => void;
  onFactoryReset: () => void;
}) {
  const [resetWord, setResetWord] = useState("");
  return (
    <div className="mt-6">
      <Card padding="md">
        {showReview && (
          <>
            <p className="mb-3 text-xs text-(--text-muted)">
              Commit applies reviewed changes. Commit-confirmed applies them temporarily and automatically rolls back unless you Confirm before the deadline.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              {canEdit && (
                <button
                  onClick={onCommit}
                  disabled={!canCommit}
                  className="rounded-xs bg-(--amber) px-3 py-1.5 text-sm font-medium text-white hover:brightness-110 transition-ui disabled:opacity-50"
                >
                  Commit
                </button>
              )}
              <div className="flex flex-wrap items-center gap-2">
                {canEdit && (
                  <button
                    onClick={onCommitConfirmed}
                    disabled={!canCommit}
                    className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
                  >
                    Commit-confirmed
                  </button>
                )}
                <input
                  aria-label="Commit-confirmed seconds"
                  value={ttlSeconds}
                  onChange={(e) => onTtlChange(e.target.value)}
                  disabled={!canEdit}
                  className="w-20 rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui outline-hidden"
                />
                <span className="text-xs text-(--text)">seconds</span>
              </div>
            </div>
          </>
        )}
        <div className={showReview ? "mt-4" : ""}>
          <Disclosure title="Recovery">
            <p className="mb-3 text-xs text-(--text-muted)">Rollback restores the previous committed configuration while keeping the newer staged candidate. Review it before any later commit.</p>
            {canEdit && <div className="flex flex-wrap gap-2">
              {!pendingConfirm && <button
                onClick={onConfirmCommit}
                disabled={!canMutate}
                className="rounded-xs border bg-(--surface) px-3 py-1.5 text-sm text-(--text) transition-ui disabled:opacity-50"
              >
                Confirm
              </button>}
              <button
                onClick={onRollback}
                disabled={!canMutate}
                className="rounded-xs bg-red-600/20 px-3 py-1.5 text-sm text-red-400 hover:bg-red-600/30 transition-ui disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Rollback
              </button>
            </div>}
            {canEdit && <div className="mt-4 grid gap-2 border-t pt-3 text-sm">
              <p>Factory reset immediately applies appliance defaults, wipes configuration, users and audit history, and resets the admin login. Sessions are revoked. {factoryResetLoginGuidance(profile, labMode)} TLS identity files are preserved. Back up first. This is not a staged edit.</p>
              <label className="grid gap-1">Type NUCLEAR to allow factory reset
                <input aria-label="Factory reset confirmation" autoComplete="off" value={resetWord}
                  onChange={e => setResetWord(e.target.value)} className="w-full input-industrial" />
              </label>
              <button disabled={!canMutate || resetWord.trim() !== "NUCLEAR"}
                className="justify-self-start rounded-xs border px-3 py-2 text-red-400 disabled:opacity-50"
                onClick={() => { setResetWord(""); onFactoryReset(); }}>Factory reset</button>
            </div>}
          </Disclosure>
        </div>
      </Card>
    </div>
  );
}
