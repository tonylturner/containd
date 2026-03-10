"use client";

import { useEffect, useState } from "react";

import { Shell } from "../../../components/Shell";
import { Card } from "../../../components/Card";
import { ConfirmDialog, useConfirm } from "../../../components/ConfirmDialog";
import { api, isAdmin, type User, type UserRole } from "../../../lib/api";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function UsersPage() {
  const confirm = useConfirm();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saveState, setSaveState] = useState<SaveState>("idle");
  const [editingUserId, setEditingUserId] = useState<string | null>(null);
  const [editDraft, setEditDraft] = useState<{
    firstName: string;
    lastName: string;
    email: string;
    role: UserRole;
  } | null>(null);
  const [query, setQuery] = useState("");

  const [newUser, setNewUser] = useState<{
    username: string;
    firstName: string;
    lastName: string;
    email: string;
    role: UserRole;
    password: string;
  }>({
    username: "",
    firstName: "",
    lastName: "",
    email: "",
    role: "view",
    password: "",
  });

  // Reset password modal state
  const [resetPwUserId, setResetPwUserId] = useState<string | null>(null);
  const [resetPwValue, setResetPwValue] = useState("");

  async function refresh() {
    if (!isAdmin()) {
      setUsers([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    const list = await api.listUsers();
    setUsers(list ?? []);
    setLoading(false);
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onCreate() {
    setError(null);
    setSaveState("saving");
    const created = await api.createUser(newUser as any);
    if (!created) {
      setSaveState("error");
      setError("Failed to create user.");
      setTimeout(() => setSaveState("idle"), 5000);
      return;
    }
    setNewUser({
      username: "",
      firstName: "",
      lastName: "",
      email: "",
      role: "view",
      password: "",
    });
    await refresh();
    setSaveState("saved");
    setTimeout(() => setSaveState("idle"), 1200);
  }

  function startEdit(user: User) {
    setEditingUserId(user.id);
    setEditDraft({
      firstName: user.firstName ?? "",
      lastName: user.lastName ?? "",
      email: user.email ?? "",
      role: user.role,
    });
  }

  function cancelEdit() {
    setEditingUserId(null);
    setEditDraft(null);
  }

  async function saveEdit(id: string) {
    if (!editDraft) return;
    setError(null);
    setSaveState("saving");
    const updated = await api.updateUser(id, editDraft);
    if (!updated) {
      setSaveState("error");
      setError("Failed to update user.");
      setTimeout(() => setSaveState("idle"), 5000);
      return;
    }
    await refresh();
    setSaveState("saved");
    setEditingUserId(null);
    setEditDraft(null);
    setTimeout(() => setSaveState("idle"), 1200);
  }

  function onResetPassword(id: string) {
    setResetPwUserId(id);
    setResetPwValue("");
  }

  async function submitResetPassword() {
    if (!resetPwUserId || !resetPwValue) return;
    setError(null);
    setSaveState("saving");
    const ok = await api.setUserPassword(resetPwUserId, resetPwValue);
    if (!ok) {
      setSaveState("error");
      setError("Failed to set password.");
      setTimeout(() => setSaveState("idle"), 5000);
      return;
    }
    setResetPwUserId(null);
    setResetPwValue("");
    setSaveState("saved");
    setTimeout(() => setSaveState("idle"), 1200);
  }

  function onDeleteUser(user: User) {
    if (!isAdmin()) return;
    confirm.open({
      title: "Delete User",
      message: `Delete user ${user.username}? This cannot be undone.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: async () => {
        setError(null);
        setSaveState("saving");
        const ok = await api.deleteUser(user.id);
        if (!ok) {
          setSaveState("error");
          setError("Failed to delete user. Ensure at least one admin remains.");
          setTimeout(() => setSaveState("idle"), 5000);
          return;
        }
        await refresh();
        setSaveState("saved");
        setTimeout(() => setSaveState("idle"), 1200);
      },
    });
  }

  return (
    <Shell title="User Management">
      <ConfirmDialog {...confirm.props} />

      {/* Reset password modal */}
      {resetPwUserId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 animate-fade-in" role="dialog" aria-modal="true">
          <div className="w-full max-w-sm rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-6 shadow-card-lg animate-slide-down">
            <h2 className="text-base font-semibold text-[var(--text)]">Reset Password</h2>
            <div className="mt-3">
              <input
                type="password"
                value={resetPwValue}
                onChange={(e) => setResetPwValue(e.target.value)}
                placeholder="Enter new password"
                autoFocus
                className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <div className="mt-5 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => { setResetPwUserId(null); setResetPwValue(""); }}
                className="rounded-sm border border-amber-500/[0.15] bg-[var(--surface2)] px-4 py-2 text-sm text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={submitResetPassword}
                disabled={!resetPwValue}
                className="rounded-sm bg-[var(--amber)] px-4 py-2 text-sm font-medium text-white transition-ui hover:brightness-110 disabled:opacity-60"
              >
                Set Password
              </button>
            </div>
          </div>
        </div>
      )}

      {!isAdmin() && (
        <div className="mb-4 rounded-sm border border-amber-400/30 bg-amber-500/10 p-4 text-sm text-amber-400">
          Admin access required.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-sm border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 opacity-100">
        <Card padding="lg">
          <h2 className="text-lg font-semibold text-[var(--text)]">Users</h2>
          <p className="mt-1 text-sm text-[var(--text)]">
            Manage local accounts and roles.
          </p>

          <div className="mt-4">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search users (name, email, role)"
              className="w-full input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
          </div>

          <div className="mt-4 overflow-hidden rounded-sm border border-amber-500/[0.15] bg-[var(--surface)]">
            <table className="w-full text-sm">
              <thead className="bg-[var(--surface)] text-left text-xs uppercase tracking-wide text-[var(--text)]">
                <tr>
                  <th className="px-4 py-3">Username</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Email</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Updated</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={6}>
                      Loading…
                    </td>
                  </tr>
                )}
                {!loading && users.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-[var(--text-muted)]" colSpan={6}>
                      No users found.
                    </td>
                  </tr>
                )}
                {users
                  .filter((u) => {
                    const q = query.trim().toLowerCase();
                    if (!q) return true;
                    const hay = [
                      u.username,
                      u.firstName,
                      u.lastName,
                      u.email,
                      u.role,
                    ]
                      .filter(Boolean)
                      .join(" ")
                      .toLowerCase();
                    return hay.includes(q);
                  })
                  .map((u) => (
                  <tr key={u.id} className="border-t border-amber-500/[0.1] table-row-hover transition-ui">
                    <td className="px-4 py-3 text-[var(--text)]">{u.username}</td>
                    <td className="px-4 py-3 text-[var(--text)]">
                      {editingUserId === u.id && editDraft ? (
                        <div className="grid gap-1">
                          <input
                            value={editDraft.firstName}
                            onChange={(e) =>
                              setEditDraft((d) => d ? { ...d, firstName: e.target.value } : d)
                            }
                            disabled={!isAdmin()}
                            placeholder="first name"
                            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                          />
                          <input
                            value={editDraft.lastName}
                            onChange={(e) =>
                              setEditDraft((d) => d ? { ...d, lastName: e.target.value } : d)
                            }
                            disabled={!isAdmin()}
                            placeholder="last name"
                            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                          />
                        </div>
                      ) : (
                        (u.firstName || "") + " " + (u.lastName || "")
                      )}
                    </td>
                    <td className="px-4 py-3 text-[var(--text)]">
                      {editingUserId === u.id && editDraft ? (
                        <input
                          value={editDraft.email}
                          onChange={(e) =>
                            setEditDraft((d) => d ? { ...d, email: e.target.value } : d)
                          }
                          disabled={!isAdmin()}
                          placeholder="email"
                          className="w-full rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                        />
                      ) : (
                        u.email ?? ""
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {editingUserId === u.id && editDraft ? (
                        <select
                          value={editDraft.role}
                          onChange={(e) =>
                            setEditDraft((d) => d ? { ...d, role: e.target.value as UserRole } : d)
                          }
                          disabled={!isAdmin()}
                          className="rounded-md border border-amber-500/[0.15] bg-[var(--surface)] px-2 py-1 text-sm text-[var(--text)] transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
                        >
                          <option value="view">view-only</option>
                          <option value="admin">admin</option>
                        </select>
                      ) : (
                        <span className="rounded-full bg-amber-500/[0.1] px-2 py-1 text-xs text-[var(--text)]">
                          {u.role}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--text-muted)]">
                      {formatTimestamp(u.updatedAt ?? u.createdAt)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {editingUserId === u.id ? (
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => saveEdit(u.id)}
                            disabled={!isAdmin()}
                            className="rounded-md bg-[var(--amber)] px-2 py-1 text-xs font-medium text-white transition-ui hover:brightness-110"
                          >
                            Save
                          </button>
                          <button
                            onClick={cancelEdit}
                            className="rounded-md border border-amber-500/[0.15] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => startEdit(u)}
                            disabled={!isAdmin()}
                            className="rounded-md border border-amber-500/[0.15] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => onResetPassword(u.id)}
                            disabled={!isAdmin()}
                            className="rounded-md border border-amber-500/[0.15] bg-[var(--surface2)] px-2 py-1 text-xs text-[var(--text)] transition-ui hover:bg-amber-500/[0.08]"
                          >
                            Reset password
                          </button>
                          <button
                            onClick={() => onDeleteUser(u)}
                            disabled={!isAdmin()}
                            className="rounded-md bg-red-600/20 px-2 py-1 text-xs text-red-400 transition-ui hover:bg-red-500/10"
                          >
                            Delete
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

        <Card padding="lg">
          <h2 className="text-lg font-semibold text-[var(--text)]">Add User</h2>
          <div className="mt-4 grid gap-2">
            <input
              value={newUser.username}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, username: e.target.value }))
              }
              disabled={!isAdmin()}
              placeholder="username"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <div className="grid gap-2 md:grid-cols-2">
              <input
                value={newUser.firstName}
                onChange={(e) =>
                  setNewUser((n) => ({ ...n, firstName: e.target.value }))
                }
                disabled={!isAdmin()}
                placeholder="first name"
                className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
              <input
                value={newUser.lastName}
                onChange={(e) =>
                  setNewUser((n) => ({ ...n, lastName: e.target.value }))
                }
                disabled={!isAdmin()}
                placeholder="last name"
                className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
              />
            </div>
            <input
              value={newUser.email}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, email: e.target.value }))
              }
              disabled={!isAdmin()}
              placeholder="email"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <select
              value={newUser.role}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, role: e.target.value as UserRole }))
              }
              disabled={!isAdmin()}
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            >
              <option value="view">view-only</option>
              <option value="admin">admin</option>
            </select>
            <p className="text-xs text-[var(--text-muted)]">
              Admins can manage users and system settings; view-only accounts have read access.
            </p>
            <input
              type="password"
              value={newUser.password}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, password: e.target.value }))
              }
              disabled={!isAdmin()}
              placeholder="password"
              className="input-industrial transition-ui focus:border-amber-500/40 focus-visible:shadow-focus-ring outline-none"
            />
            <button
              onClick={onCreate}
              disabled={!isAdmin()}
              className="mt-2 rounded-sm bg-[var(--amber)] px-3 py-2 text-sm font-medium text-white transition-ui hover:brightness-110"
            >
              Create user
            </button>
          </div>
        </Card>
      </div>
    </Shell>
  );
}

function formatTimestamp(value?: string) {
  if (!value) return "—";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return "—";
  return dt.toLocaleString();
}
