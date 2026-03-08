"use client";

import { useEffect, useState } from "react";

import { Shell } from "../../../components/Shell";
import { api, isAdmin, type User, type UserRole } from "../../../lib/api";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function UsersPage() {
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

  async function onResetPassword(id: string) {
    const pw = prompt("Enter new password:");
    if (!pw) return;
    setError(null);
    setSaveState("saving");
    const ok = await api.setUserPassword(id, pw);
    if (!ok) {
      setSaveState("error");
      setError("Failed to set password.");
      setTimeout(() => setSaveState("idle"), 5000);
      return;
    }
    setSaveState("saved");
    setTimeout(() => setSaveState("idle"), 1200);
  }

  async function onDeleteUser(user: User) {
    if (!isAdmin()) return;
    const confirmed = confirm(`Delete user ${user.username}? This cannot be undone.`);
    if (!confirmed) return;
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
  }

  return (
    <Shell title="User Management">
      {!isAdmin() && (
        <div className="mb-4 rounded-xl border border-amber/30 bg-amber/10 p-4 text-sm text-amber">
          Admin access required.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 opacity-100">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Users</h2>
          <p className="mt-1 text-sm text-slate-300">
            Manage local accounts and roles.
          </p>

          <div className="mt-4">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search users (name, email, role)"
              className="w-full rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white placeholder:text-slate-500"
            />
          </div>

          <div className="mt-4 overflow-hidden rounded-xl border border-white/10 bg-black/30">
            <table className="w-full text-sm">
              <thead className="bg-black/40 text-left text-xs uppercase tracking-wide text-slate-300">
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
                    <td className="px-4 py-4 text-slate-400" colSpan={6}>
                      Loading…
                    </td>
                  </tr>
                )}
                {!loading && users.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-slate-400" colSpan={6}>
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
                  <tr key={u.id} className="border-t border-white/5">
                    <td className="px-4 py-3 text-slate-200">{u.username}</td>
                    <td className="px-4 py-3 text-slate-200">
                      {editingUserId === u.id && editDraft ? (
                        <div className="grid gap-1">
                          <input
                            value={editDraft.firstName}
                            onChange={(e) =>
                              setEditDraft((d) => d ? { ...d, firstName: e.target.value } : d)
                            }
                            disabled={!isAdmin()}
                            placeholder="first name"
                            className="rounded-md border border-white/10 bg-black/40 px-2 py-1 text-xs text-white"
                          />
                          <input
                            value={editDraft.lastName}
                            onChange={(e) =>
                              setEditDraft((d) => d ? { ...d, lastName: e.target.value } : d)
                            }
                            disabled={!isAdmin()}
                            placeholder="last name"
                            className="rounded-md border border-white/10 bg-black/40 px-2 py-1 text-xs text-white"
                          />
                        </div>
                      ) : (
                        (u.firstName || "") + " " + (u.lastName || "")
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-200">
                      {editingUserId === u.id && editDraft ? (
                        <input
                          value={editDraft.email}
                          onChange={(e) =>
                            setEditDraft((d) => d ? { ...d, email: e.target.value } : d)
                          }
                          disabled={!isAdmin()}
                          placeholder="email"
                          className="w-full rounded-md border border-white/10 bg-black/40 px-2 py-1 text-xs text-white"
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
                          className="rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
                        >
                          <option value="view">view-only</option>
                          <option value="admin">admin</option>
                        </select>
                      ) : (
                        <span className="rounded-full bg-white/10 px-2 py-1 text-xs text-slate-200">
                          {u.role}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {formatTimestamp(u.updatedAt ?? u.createdAt)}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {editingUserId === u.id ? (
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => saveEdit(u.id)}
                            disabled={!isAdmin()}
                            className="rounded-md bg-mint/20 px-2 py-1 text-xs text-mint hover:bg-mint/30"
                          >
                            Save
                          </button>
                          <button
                            onClick={cancelEdit}
                            className="rounded-md border border-white/10 px-2 py-1 text-xs text-slate-300 hover:bg-white/10"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => startEdit(u)}
                            disabled={!isAdmin()}
                            className="rounded-md border border-white/10 px-2 py-1 text-xs text-slate-200 hover:bg-white/10"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => onResetPassword(u.id)}
                            disabled={!isAdmin()}
                            className="rounded-md bg-white/10 px-2 py-1 text-xs text-white hover:bg-white/20"
                          >
                            Reset password
                          </button>
                          <button
                            onClick={() => onDeleteUser(u)}
                            disabled={!isAdmin()}
                            className="rounded-md bg-[color:var(--error)]/10 px-2 py-1 text-xs text-[color:var(--error)] hover:bg-[color:var(--error)]/20"
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

        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Add User</h2>
          <div className="mt-4 grid gap-2">
            <input
              value={newUser.username}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, username: e.target.value }))
              }
              disabled={!isAdmin()}
              placeholder="username"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <div className="grid gap-2 md:grid-cols-2">
              <input
                value={newUser.firstName}
                onChange={(e) =>
                  setNewUser((n) => ({ ...n, firstName: e.target.value }))
                }
                disabled={!isAdmin()}
                placeholder="first name"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
              <input
                value={newUser.lastName}
                onChange={(e) =>
                  setNewUser((n) => ({ ...n, lastName: e.target.value }))
                }
                disabled={!isAdmin()}
                placeholder="last name"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
            </div>
            <input
              value={newUser.email}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, email: e.target.value }))
              }
              disabled={!isAdmin()}
              placeholder="email"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <select
              value={newUser.role}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, role: e.target.value as UserRole }))
              }
              disabled={!isAdmin()}
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            >
              <option value="view">view-only</option>
              <option value="admin">admin</option>
            </select>
            <p className="text-xs text-slate-400">
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
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <button
              onClick={onCreate}
              disabled={!isAdmin()}
              className="mt-2 rounded-lg bg-mint/20 px-3 py-2 text-sm text-mint hover:bg-mint/30"
            >
              Create user
            </button>
          </div>
        </div>
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
