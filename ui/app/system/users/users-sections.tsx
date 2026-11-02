"use client";

import { Card } from "../../../components/Card";
import type { User, UserRole } from "../../../lib/api";

/** The user action in flight: create, or edit/password/delete of one user. */
export type PendingAction =
  | "create"
  | `edit:${string}`
  | `password:${string}`
  | `delete:${string}`
  | `mfa-require:${string}`
  | `mfa-grace:${string}`
  | `mfa-clear:${string}`
  | `mfa-disable:${string}`
  | null;

function formatTimestamp(value?: string) {
  if (!value) return "—";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "—";
  return dt.toLocaleString();
}

function formatMFAGrace(value?: string) {
  if (!value) return "Setup required now";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "Setup required now";
  if (dt.getTime() <= Date.now()) return "Grace expired";
  return `Grace until ${dt.toLocaleString()}`;
}

export function ResetPasswordModal({
  open,
  value,
  onChange,
  onCancel,
  onSubmit,
  pending,
}: {
  open: boolean;
  value: string;
  onChange: (value: string) => void;
  onCancel: () => void;
  onSubmit: () => void;
  /** The password is being set: no second submit. */
  pending: boolean;
}) {
  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 animate-fade-in"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-sm rounded-xs border bg-(--surface) p-6 shadow-card-lg animate-slide-down">
        <h2 className="text-base font-semibold text-(--text)">
          Reset Password
        </h2>
        <div className="mt-3">
          <input
            type="password"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Enter new password"
            autoFocus
            className="w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
        </div>
        <div className="mt-5 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-xs border bg-(--surface2) px-4 py-2 text-sm text-(--text) transition-ui"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onSubmit}
            disabled={!value || pending}
            className="rounded-xs bg-(--amber) px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
          >
            {pending ? "Setting\u2026" : "Set Password"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function ManageUsersPanel({
  loading,
  users,
  query,
  onQueryChange,
  canEdit,
  editingUserId,
  editDraft,
  setEditDraft,
  startEdit,
  cancelEdit,
  saveEdit,
  onResetPassword,
  onDeleteUser,
  onDisableUserMFA,
  onRequireUserMFA,
  onClearUserMFARequirement,
  onExtendUserMFAGrace,
  pending,
}: {
  loading: boolean;
  users: User[];
  query: string;
  onQueryChange: (value: string) => void;
  canEdit: boolean;
  editingUserId: string | null;
  editDraft: {
    firstName: string;
    lastName: string;
    email: string;
    role: UserRole;
  } | null;
  setEditDraft: (
    updater: (
      current: {
        firstName: string;
        lastName: string;
        email: string;
        role: UserRole;
      } | null,
    ) => {
      firstName: string;
      lastName: string;
      email: string;
      role: UserRole;
    } | null,
  ) => void;
  startEdit: (user: User) => void;
  cancelEdit: () => void;
  saveEdit: (id: string) => void;
  onResetPassword: (id: string) => void;
  onDeleteUser: (user: User) => void;
  onDisableUserMFA: (user: User) => void;
  onRequireUserMFA: (user: User) => void;
  onClearUserMFARequirement: (user: User) => void;
  onExtendUserMFAGrace: (user: User) => void;
  /** The action in flight; its button is disabled until it finishes. */
  pending: PendingAction;
}) {
  const filteredUsers = users.filter((u) => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    const hay = [u.username, u.firstName, u.lastName, u.email, u.role]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });

  return (
    <Card padding="lg">
      <h2 className="text-lg font-semibold text-(--text)">Users</h2>
      <p className="mt-1 text-sm text-(--text)">
        Manage local accounts, roles, and MFA requirements.
      </p>

      <div className="mt-4">
        <input
          value={query}
          onChange={(e) => onQueryChange(e.target.value)}
          placeholder="Search users (name, email, role)"
          className="w-full input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
        />
      </div>

      <div className="mt-4 overflow-x-auto rounded-xs border bg-(--surface)">
        <table className="w-full text-sm max-md:block max-md:[&_tbody]:block max-md:[&_tr]:block max-md:[&_td]:block max-md:[&_td]:break-words max-md:[&_td]:py-2">
          <thead className="max-md:sr-only bg-(--surface) text-left text-xs uppercase tracking-wide text-(--text)">
            <tr>
              <th className="px-4 py-3">Username</th>
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Email</th>
              <th className="px-4 py-3">Role</th>
              <th className="px-4 py-3">MFA Policy</th>
              <th className="px-4 py-3">Updated</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td
                  className="px-4 py-4 text-(--text-muted)"
                  colSpan={7}
                >
                  Loading…
                </td>
              </tr>
            )}
            {!loading && users.length === 0 && (
              <tr>
                <td
                  className="px-4 py-4 text-(--text-muted)"
                  colSpan={7}
                >
                  No users found.
                </td>
              </tr>
            )}
            {filteredUsers.map((u) => (
              <tr
                key={u.id}
                className="border-t table-row-hover transition-ui"
              >
                <td className="px-4 py-3 text-(--text)"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">Username</span>{u.username}</td>
                <td className="px-4 py-3 text-(--text)"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">Name</span>
                  {editingUserId === u.id && editDraft ? (
                    <div className="grid gap-1">
                      <input
                        value={editDraft.firstName}
                        onChange={(e) =>
                          setEditDraft((d) =>
                            d ? { ...d, firstName: e.target.value } : d,
                          )
                        }
                        disabled={!canEdit}
                        placeholder="first name"
                        className="rounded-md border bg-(--surface) px-2 py-1 text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
                      />
                      <input
                        value={editDraft.lastName}
                        onChange={(e) =>
                          setEditDraft((d) =>
                            d ? { ...d, lastName: e.target.value } : d,
                          )
                        }
                        disabled={!canEdit}
                        placeholder="last name"
                        className="rounded-md border bg-(--surface) px-2 py-1 text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
                      />
                    </div>
                  ) : (
                    (u.firstName || "") + " " + (u.lastName || "")
                  )}
                </td>
                <td className="px-4 py-3 text-(--text)"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">Email</span>
                  {editingUserId === u.id && editDraft ? (
                    <input
                      value={editDraft.email}
                      onChange={(e) =>
                        setEditDraft((d) =>
                          d ? { ...d, email: e.target.value } : d,
                        )
                      }
                      disabled={!canEdit}
                      placeholder="email"
                      className="w-full rounded-md border bg-(--surface) px-2 py-1 text-xs text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
                    />
                  ) : (
                    u.email ?? ""
                  )}
                </td>
                <td className="px-4 py-3"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">Role</span>
                  {editingUserId === u.id && editDraft ? (
                    <select
                      value={editDraft.role}
                      onChange={(e) =>
                        setEditDraft((d) =>
                          d ? { ...d, role: e.target.value as UserRole } : d,
                        )
                      }
                      disabled={!canEdit}
                      className="rounded-md border bg-(--surface) px-2 py-1 text-sm text-(--text) transition-ui focus-visible:shadow-focus-ring outline-hidden"
                    >
                      <option value="view">view-only</option>
                      <option value="admin">admin</option>
                    </select>
                  ) : (
                    <span className="rounded-full px-2 py-1 text-xs text-(--text)">
                      {u.role}
                    </span>
                  )}
                </td>
                <td className="px-4 py-3"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">MFA Policy</span>
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-full px-2 py-1 text-xs ${u.mfaEnabled ? "bg-emerald-500/10 text-emerald-400" : "bg-white/6 text-(--text-muted)"}`}
                    >
                      {u.mfaEnabled ? "enabled" : "disabled"}
                    </span>
                    {u.mfaRequired && (
                      <span className="rounded-full px-2 py-1 text-xs">
                        required
                      </span>
                    )}
                  </div>
                  {u.mfaRequired && !u.mfaEnabled && (
                    <div className="mt-1 text-xs text-(--text-muted)">
                      {formatMFAGrace(u.mfaGraceUntil)}
                    </div>
                  )}
                </td>
                <td className="px-4 py-3 text-xs text-(--text-muted)"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">Updated</span>
                  {formatTimestamp(u.updatedAt ?? u.createdAt)}
                </td>
                <td className="px-4 py-3 text-right"><span className="mb-1 block text-xs text-(--text-muted) md:hidden">Actions</span>
                  {editingUserId === u.id ? (
                    <div className="flex flex-wrap justify-end gap-2">
                      <button
                        onClick={() => saveEdit(u.id)}
                        disabled={!canEdit || pending === `edit:${u.id}`}
                        className="rounded-md bg-(--amber) px-2 py-1 text-xs font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
                      >
                        {pending === `edit:${u.id}` ? "Saving\u2026" : "Save"}
                      </button>
                      <button
                        onClick={cancelEdit}
                        className="rounded-md border px-2 py-1 text-xs text-(--text) transition-ui"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <div className="flex flex-wrap justify-end gap-2">
                      <button
                        onClick={() => startEdit(u)}
                        disabled={!canEdit}
                        className="rounded-md border px-2 py-1 text-xs text-(--text) transition-ui"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => onResetPassword(u.id)}
                        disabled={!canEdit}
                        className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui"
                      >
                        Reset password
                      </button>
                      {!u.mfaRequired && (
                        <button
                          onClick={() => onRequireUserMFA(u)}
                          disabled={!canEdit || pending === `mfa-require:${u.id}`}
                          className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui disabled:opacity-60"
                        >
                          {pending === `mfa-require:${u.id}` ? "Requiring\u2026" : "Require MFA"}
                        </button>
                      )}
                      {u.mfaRequired && !u.mfaEnabled && (
                        <button
                          onClick={() => onExtendUserMFAGrace(u)}
                          disabled={!canEdit || pending === `mfa-grace:${u.id}`}
                          className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui disabled:opacity-60"
                        >
                          {pending === `mfa-grace:${u.id}` ? "Extending\u2026" : "Extend grace"}
                        </button>
                      )}
                      {u.mfaRequired && (
                        <button
                          onClick={() => onClearUserMFARequirement(u)}
                          disabled={!canEdit || pending === `mfa-clear:${u.id}`}
                          className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui disabled:opacity-60"
                        >
                          {pending === `mfa-clear:${u.id}` ? "Clearing\u2026" : "Clear MFA req"}
                        </button>
                      )}
                      {u.mfaEnabled && (
                        <button
                          onClick={() => onDisableUserMFA(u)}
                          disabled={!canEdit || pending === `mfa-disable:${u.id}`}
                          className="rounded-md border bg-(--surface2) px-2 py-1 text-xs text-(--text) transition-ui disabled:opacity-60"
                        >
                          {pending === `mfa-disable:${u.id}` ? "Disabling\u2026" : u.mfaRequired ? "Reset MFA" : "Disable MFA"}
                        </button>
                      )}
                      <button
                        onClick={() => onDeleteUser(u)}
                        disabled={!canEdit || pending === `delete:${u.id}`}
                        className="rounded-md bg-red-600/20 px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10 disabled:opacity-60"
                      >
                        {pending === `delete:${u.id}` ? "Deleting\u2026" : "Delete"}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function CreateUserPanel({
  canEdit,
  newUser,
  setNewUser,
  onCreate,
  pending,
}: {
  canEdit: boolean;
  newUser: {
    username: string;
    firstName: string;
    lastName: string;
    email: string;
    role: UserRole;
    password: string;
  };
  setNewUser: (
    updater: (current: {
      username: string;
      firstName: string;
      lastName: string;
      email: string;
      role: UserRole;
      password: string;
    }) => {
      username: string;
      firstName: string;
      lastName: string;
      email: string;
      role: UserRole;
      password: string;
    },
  ) => void;
  onCreate: () => void;
  /** The user is being created: no second submit. */
  pending: boolean;
}) {
  return (
    <Card padding="lg">
      <h2 className="text-lg font-semibold text-(--text)">Add User</h2>
      <p className="mt-1 text-sm text-(--text)">
        Create a local account, then require MFA if the account should use an
        authenticator app after first sign-in.
      </p>
      <div className="mt-4 grid max-w-2xl gap-2">
        <input
          value={newUser.username}
          onChange={(e) =>
            setNewUser((n) => ({ ...n, username: e.target.value }))
          }
          disabled={!canEdit}
          placeholder="username"
          className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
        />
        <div className="grid gap-2 md:grid-cols-2">
          <input
            value={newUser.firstName}
            onChange={(e) =>
              setNewUser((n) => ({ ...n, firstName: e.target.value }))
            }
            disabled={!canEdit}
            placeholder="first name"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
          <input
            value={newUser.lastName}
            onChange={(e) =>
              setNewUser((n) => ({ ...n, lastName: e.target.value }))
            }
            disabled={!canEdit}
            placeholder="last name"
            className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
          />
        </div>
        <input
          value={newUser.email}
          onChange={(e) =>
            setNewUser((n) => ({ ...n, email: e.target.value }))
          }
          disabled={!canEdit}
          placeholder="email"
          className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
        />
        <select
          value={newUser.role}
          onChange={(e) =>
            setNewUser((n) => ({ ...n, role: e.target.value as UserRole }))
          }
          disabled={!canEdit}
          className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
        >
          <option value="view">view-only</option>
          <option value="admin">admin</option>
        </select>
        <p className="text-xs text-(--text-muted)">
          Admins can manage users and system settings; view-only accounts have
          read access.
        </p>
        <input
          type="password"
          value={newUser.password}
          onChange={(e) =>
            setNewUser((n) => ({ ...n, password: e.target.value }))
          }
          disabled={!canEdit}
          placeholder="password"
          className="input-industrial transition-ui focus-visible:shadow-focus-ring outline-hidden"
        />
        <button
          onClick={onCreate}
          disabled={!canEdit || pending}
          className="mt-2 rounded-xs bg-(--amber) px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
        >
          {pending ? "Creating\u2026" : "Create user"}
        </button>
      </div>
    </Card>
  );
}
