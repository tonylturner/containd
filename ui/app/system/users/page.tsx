"use client";

import { useEffect, useState } from "react";

import { Shell } from "../../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../../components/ConfirmDialog";
import { api, isAdmin, type User, type UserRole } from "../../../lib/api";
import {
  CreateUserPanel,
  ManageUsersPanel,
  ResetPasswordModal,
} from "./users-sections";

type SaveState = "idle" | "saving" | "saved" | "error";
type UsersTab = "manage" | "create";

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
  const [activeTab, setActiveTab] = useState<UsersTab>("manage");

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
    if (!created.ok) {
      setSaveState("error");
      setError(created.error || "Failed to create user.");
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
    if (!updated.ok) {
      setSaveState("error");
      setError(updated.error || "Failed to update user.");
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
    if (!ok.ok) {
      setSaveState("error");
      setError(ok.error || "Failed to set password.");
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
        if (!ok.ok) {
          setSaveState("error");
          setError(
            ok.error ||
              "Failed to delete user. Ensure at least one admin remains.",
          );
          setTimeout(() => setSaveState("idle"), 5000);
          return;
        }
        await refresh();
        setSaveState("saved");
        setTimeout(() => setSaveState("idle"), 1200);
      },
    });
  }

  function onDisableUserMFA(user: User) {
    if (!isAdmin()) return;
    confirm.open({
      title: "Disable MFA",
      message: `Disable MFA for ${user.username}? They will be able to sign in with only their password until they re-enable MFA.`,
      confirmLabel: "Disable MFA",
      variant: "warning",
      onConfirm: async () => {
        setError(null);
        setSaveState("saving");
        const ok = await api.disableUserMFA(user.id);
        if (!ok.ok) {
          setSaveState("error");
          setError(ok.error || "Failed to disable MFA.");
          setTimeout(() => setSaveState("idle"), 5000);
          return;
        }
        await refresh();
        setSaveState("saved");
        setTimeout(() => setSaveState("idle"), 1200);
      },
    });
  }

  function onRequireUserMFA(user: User) {
    if (!isAdmin()) return;
    confirm.open({
      title: "Require MFA",
      message: user.mfaEnabled
        ? `Require MFA for ${user.username}? Their next login will require their authenticator app.`
        : `Require MFA for ${user.username}? They will have 7 days to set it up before full access is restricted.`,
      confirmLabel: "Require MFA",
      variant: "warning",
      onConfirm: async () => {
        setError(null);
        setSaveState("saving");
        const ok = await api.requireUserMFA(user.id);
        if (!ok.ok) {
          setSaveState("error");
          setError(ok.error || "Failed to require MFA.");
          setTimeout(() => setSaveState("idle"), 5000);
          return;
        }
        await refresh();
        setSaveState("saved");
        setTimeout(() => setSaveState("idle"), 1200);
      },
    });
  }

  function onClearUserMFARequirement(user: User) {
    if (!isAdmin()) return;
    confirm.open({
      title: "Clear MFA Requirement",
      message: `Clear the MFA requirement for ${user.username}?`,
      confirmLabel: "Clear requirement",
      variant: "warning",
      onConfirm: async () => {
        setError(null);
        setSaveState("saving");
        const ok = await api.clearUserMFARequirement(user.id);
        if (!ok.ok) {
          setSaveState("error");
          setError(ok.error || "Failed to clear MFA requirement.");
          setTimeout(() => setSaveState("idle"), 5000);
          return;
        }
        await refresh();
        setSaveState("saved");
        setTimeout(() => setSaveState("idle"), 1200);
      },
    });
  }

  function onExtendUserMFAGrace(user: User) {
    if (!isAdmin()) return;
    confirm.open({
      title: "Extend MFA Grace",
      message: `Give ${user.username} another 7 days to set up MFA?`,
      confirmLabel: "Extend grace",
      variant: "warning",
      onConfirm: async () => {
        setError(null);
        setSaveState("saving");
        const ok = await api.extendUserMFAGrace(user.id);
        if (!ok.ok) {
          setSaveState("error");
          setError(ok.error || "Failed to extend MFA grace.");
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

      <ResetPasswordModal
        open={!!resetPwUserId}
        value={resetPwValue}
        onChange={setResetPwValue}
        onCancel={() => {
          setResetPwUserId(null);
          setResetPwValue("");
        }}
        onSubmit={submitResetPassword}
      />

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

      <div className="mb-4 flex max-w-md gap-1 rounded-sm border border-amber-500/[0.15] bg-[var(--surface)] p-1">
        <button
          type="button"
          onClick={() => setActiveTab("manage")}
          className={`flex-1 rounded-sm px-3 py-2 text-sm font-medium transition-ui ${activeTab === "manage" ? "bg-amber-500/[0.12] text-[var(--text)]" : "text-[var(--text-muted)] hover:bg-amber-500/[0.08]"}`}
        >
          Manage Users
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("create")}
          className={`flex-1 rounded-sm px-3 py-2 text-sm font-medium transition-ui ${activeTab === "create" ? "bg-amber-500/[0.12] text-[var(--text)]" : "text-[var(--text-muted)] hover:bg-amber-500/[0.08]"}`}
        >
          Add User
        </button>
      </div>

      {activeTab === "manage" && (
        <ManageUsersPanel
          loading={loading}
          users={users}
          query={query}
          onQueryChange={setQuery}
          canEdit={isAdmin()}
          editingUserId={editingUserId}
          editDraft={editDraft}
          setEditDraft={setEditDraft}
          startEdit={startEdit}
          cancelEdit={cancelEdit}
          saveEdit={saveEdit}
          onResetPassword={onResetPassword}
          onDeleteUser={onDeleteUser}
          onDisableUserMFA={onDisableUserMFA}
          onRequireUserMFA={onRequireUserMFA}
          onClearUserMFARequirement={onClearUserMFARequirement}
          onExtendUserMFAGrace={onExtendUserMFAGrace}
        />
      )}

      {activeTab === "create" && (
        <CreateUserPanel
          canEdit={isAdmin()}
          newUser={newUser}
          setNewUser={setNewUser}
          onCreate={onCreate}
        />
      )}
    </Shell>
  );
}
