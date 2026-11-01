import { Card } from "../../components/Card";
import { Disclosure } from "../../components/Disclosure";

export function ConfigActionBar({
  canEdit,
  canCommit,
  canMutate,
  showReview,
  pendingConfirm,
  ttlSeconds,
  onTtlChange,
  onCommit,
  onCommitConfirmed,
  onConfirmCommit,
  onRollback,
}: {
  canEdit: boolean;
  canCommit: boolean;
  canMutate: boolean;
  showReview: boolean;
  pendingConfirm: boolean;
  ttlSeconds: string;
  onTtlChange: (value: string) => void;
  onCommit: () => void;
  onCommitConfirmed: () => void;
  onConfirmCommit: () => void;
  onRollback: () => void;
}) {
  return (
    <Card className="mt-6" padding="md">
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
        </Disclosure>
      </div>
    </Card>
  );
}
