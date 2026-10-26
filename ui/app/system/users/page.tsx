"use client";

import { useEffect, useState } from "react";

import { Shell } from "../../../components/Shell";
import { ConfirmDialog, useConfirm } from "../../../components/ConfirmDialog";
import { SaveStateLine } from "../../../components/SaveStateLine";
import { useSaveAction } from "../../../hooks/useSaveAction";
import { api, isAdmin, type ApiResult, type User, type UserRole } from "../../../lib/api";
import {
  CreateUserPanel,
  ManageUsersPanel,
  ResetPasswordModal,
  type PendingAction,
} from "./users-sections";

type UsersTab = "manage" | "create";

export default function UsersPage() {
  const confirm = useConfirm();
  const save = useSaveAction<Exclude<PendingAction, null>>();
  const pending = save.pending;
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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

  /**
   * Runs one user action at a time through the shared save hook: the acting
   * button is disabled while it runs, then a toast and the state line confirm
   * it, or the error is shown. True when it succeeded.
   */
  async function runAction<T>(
    key: Exclude<PendingAction, null>,
    action: () => Promise<ApiResult<T>>,
    messages: { success: string; failure: string },
  ): Promise<boolean> {
    setError(null);
    const result = await save.run(key, action, messages);
    if (result && !result.ok) setError(result.error);
    return !!result?.ok;
  }

  async function onCreate() {
    const username = newUser.username;
    const created = await runAction("create", () => api.createUser(newUser as any), {
      success: `User ${username} created.`,
      failure: "Failed to create user.",
    });
    if (!created) return;
    setNewUser({
      username: "",
      firstName: "",
      lastName: "",
      email: "",
      role: "view",
      password: "",
    });
    await refresh();
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
    const draft = editDraft;
    const updated = await runAction(`edit:${id}`, () => api.updateUser(id, draft), {
      success: "User saved.",
      failure: "Failed to update user.",
    });
    if (!updated) return;
    await refresh();
    setEditingUserId(null);
    setEditDraft(null);
  }

  function onResetPassword(id: string) {
    setResetPwUserId(id);
    setResetPwValue("");
  }

  async function submitResetPassword() {
    if (!resetPwUserId || !resetPwValue) return;
    const id = resetPwUserId;
    const password = resetPwValue;
    const username = users.find((u) => u.id === id)?.username ?? "the user";
    const set = await runAction(`password:${id}`, () => api.setUserPassword(id, password), {
      success: `Password set for ${username}.`,
      failure: "Failed to set password.",
    });
    if (!set) return;
    setResetPwUserId(null);
    setResetPwValue("");
  }

  function onDeleteUser(user: User) {
    if (!isAdmin()) return;
    confirm.open({
      title: "Delete User",
      message: `Delete user ${user.username}? This cannot be undone.`,
      confirmLabel: "Delete",
      variant: "danger",
      onConfirm: async () => {
        const deleted = await runAction(`delete:${user.id}`, () => api.deleteUser(user.id), {
          success: `User ${user.username} deleted.`,
          failure: "Failed to delete user. Ensure at least one admin remains.",
        });
        if (deleted) await refresh();
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
        const done = await runAction(`mfa-disable:${user.id}`, () => api.disableUserMFA(user.id), {
          success: `${user.mfaRequired ? "MFA reset" : "MFA disabled"} for ${user.username}.`,
          failure: "Failed to disable MFA.",
        });
        if (done) await refresh();
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
        const done = await runAction(`mfa-require:${user.id}`, () => api.requireUserMFA(user.id), {
          success: `MFA required for ${user.username}.`,
          failure: "Failed to require MFA.",
        });
        if (done) await refresh();
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
        const done = await runAction(`mfa-clear:${user.id}`, () => api.clearUserMFARequirement(user.id), {
          success: `MFA requirement cleared for ${user.username}.`,
          failure: "Failed to clear MFA requirement.",
        });
        if (done) await refresh();
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
        const done = await runAction(`mfa-grace:${user.id}`, () => api.extendUserMFAGrace(user.id), {
          success: `MFA grace extended for ${user.username}.`,
          failure: "Failed to extend MFA grace.",
        });
        if (done) await refresh();
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
        pending={!!resetPwUserId && pending === `password:${resetPwUserId}`}
      />

      {!isAdmin() && (
        <div className="mb-4 rounded-xs border p-4 text-sm">
          Admin access required.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded-xs border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="mb-4 flex max-w-md gap-1 rounded-xs border bg-(--surface) p-1">
        <button
          type="button"
          onClick={() => setActiveTab("manage")}
          className={`flex-1 rounded-xs px-3 py-2 text-sm font-medium transition-ui ${activeTab === "manage" ? "text-(--text)" : "text-(--text-muted) "}`}
        >
          Manage Users
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("create")}
          className={`flex-1 rounded-xs px-3 py-2 text-sm font-medium transition-ui ${activeTab === "create" ? "text-(--text)" : "text-(--text-muted) "}`}
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
          pending={pending}
        />
      )}

      {activeTab === "create" && (
        <CreateUserPanel
          canEdit={isAdmin()}
          newUser={newUser}
          setNewUser={setNewUser}
          onCreate={onCreate}
          pending={pending === "create"}
        />
      )}

      <SaveStateLine state={save.state} saved="saved." />
    </Shell>
  );
}
