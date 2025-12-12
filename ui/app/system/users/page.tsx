"use client";

import { useEffect, useState } from "react";

import { Shell } from "../../../components/Shell";
import { api, type User, type UserRole } from "../../../lib/api";

type SaveState = "idle" | "saving" | "saved" | "error";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saveState, setSaveState] = useState<SaveState>("idle");

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
      setTimeout(() => setSaveState("idle"), 1500);
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

  async function onUpdateRole(id: string, role: UserRole) {
    setError(null);
    setSaveState("saving");
    const updated = await api.updateUser(id, { role });
    if (!updated) {
      setSaveState("error");
      setError("Failed to update role.");
      setTimeout(() => setSaveState("idle"), 1500);
      return;
    }
    await refresh();
    setSaveState("saved");
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
      setTimeout(() => setSaveState("idle"), 1500);
      return;
    }
    setSaveState("saved");
    setTimeout(() => setSaveState("idle"), 1200);
  }

  return (
    <Shell title="User Management">
      {error && (
        <div className="mb-4 rounded-lg border border-amber/30 bg-amber/10 px-3 py-2 text-sm text-amber">
          {error}
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Users</h2>
          <p className="mt-1 text-sm text-slate-300">
            Manage local accounts and roles.
          </p>

          <div className="mt-4 overflow-hidden rounded-xl border border-white/10 bg-black/30">
            <table className="w-full text-sm">
              <thead className="bg-black/40 text-left text-xs uppercase tracking-wide text-slate-300">
                <tr>
                  <th className="px-4 py-3">Username</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Email</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td className="px-4 py-4 text-slate-400" colSpan={5}>
                      Loading…
                    </td>
                  </tr>
                )}
                {!loading && users.length === 0 && (
                  <tr>
                    <td className="px-4 py-4 text-slate-400" colSpan={5}>
                      No users found.
                    </td>
                  </tr>
                )}
                {users.map((u) => (
                  <tr key={u.id} className="border-t border-white/5">
                    <td className="px-4 py-3 text-slate-200">{u.username}</td>
                    <td className="px-4 py-3 text-slate-200">
                      {(u.firstName || "") + " " + (u.lastName || "")}
                    </td>
                    <td className="px-4 py-3 text-slate-200">{u.email ?? ""}</td>
                    <td className="px-4 py-3">
                      <select
                        value={u.role}
                        onChange={(e) =>
                          onUpdateRole(u.id, e.target.value as UserRole)
                        }
                        className="rounded-md border border-white/10 bg-black/40 px-2 py-1 text-sm text-white"
                      >
                        <option value="view">view-only</option>
                        <option value="admin">admin</option>
                      </select>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => onResetPassword(u.id)}
                        className="rounded-md bg-white/10 px-2 py-1 text-xs text-white hover:bg-white/20"
                      >
                        Reset password
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="mt-3 text-xs text-slate-400">
            State: {saveState}
          </p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-5 shadow-lg backdrop-blur">
          <h2 className="text-lg font-semibold text-white">Add User</h2>
          <div className="mt-4 grid gap-2">
            <input
              value={newUser.username}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, username: e.target.value }))
              }
              placeholder="username"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <div className="grid gap-2 md:grid-cols-2">
              <input
                value={newUser.firstName}
                onChange={(e) =>
                  setNewUser((n) => ({ ...n, firstName: e.target.value }))
                }
                placeholder="first name"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
              <input
                value={newUser.lastName}
                onChange={(e) =>
                  setNewUser((n) => ({ ...n, lastName: e.target.value }))
                }
                placeholder="last name"
                className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
              />
            </div>
            <input
              value={newUser.email}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, email: e.target.value }))
              }
              placeholder="email"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <select
              value={newUser.role}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, role: e.target.value as UserRole }))
              }
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            >
              <option value="view">view-only</option>
              <option value="admin">admin</option>
            </select>
            <input
              type="password"
              value={newUser.password}
              onChange={(e) =>
                setNewUser((n) => ({ ...n, password: e.target.value }))
              }
              placeholder="password"
              className="rounded-lg border border-white/10 bg-black/40 px-3 py-2 text-sm text-white"
            />
            <button
              onClick={onCreate}
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
