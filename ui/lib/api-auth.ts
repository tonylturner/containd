import {
  clearAuthExpired,
  clearLocalAuth,
  setLastAuthError,
  setSessionToken,
  setStoredRole,
} from "./api-core";
import {
  deleteJSONResult,
  getJSON,
  getJSONWithStatus,
  patchJSONResult,
  postJSON,
  postJSONResult,
} from "./api-request";

import type {
  ChangePasswordRequest,
  LoginResponse,
  LoginStartResponse,
  MFADisableRequest,
  MFAEnrollResponse,
  UpdateMeRequest,
  User,
} from "./api";

export const authAPI = {
  login: async (username: string, password: string) => {
    const res = await postJSON<LoginStartResponse>("/api/v1/auth/login", {
      username,
      password,
    });
    if (res && "token" in res && res.token) setSessionToken(res.token);
    if (res && "token" in res && res.user?.role) setStoredRole(res.user.role);
    if (res) {
      clearAuthExpired();
      setLastAuthError(null);
    }
    return res;
  },
  verifyLoginMFA: async (challengeToken: string, code: string) => {
    const res = await postJSON<LoginResponse>("/api/v1/auth/login/mfa", {
      challengeToken,
      code,
    });
    if (res?.token) setSessionToken(res.token);
    if (res?.user?.role) setStoredRole(res.user.role);
    if (res) {
      clearAuthExpired();
      setLastAuthError(null);
    }
    return res;
  },
  logout: async () => {
    const ok = await postJSON<{ status: string }>("/api/v1/auth/logout", {});
    clearLocalAuth();
    return ok;
  },
  me: async () => {
    const u = await getJSON<User>("/api/v1/auth/me");
    if (u?.role) setStoredRole(u.role);
    if (u) {
      clearAuthExpired();
      setLastAuthError(null);
    }
    return u;
  },
  meStatus: async () => {
    const res = await getJSONWithStatus<User>("/api/v1/auth/me");
    if (res.data?.role) setStoredRole(res.data.role);
    if (res.status === 200) {
      clearAuthExpired();
      setLastAuthError(null);
    }
    return res;
  },
  updateMe: (patch: UpdateMeRequest) =>
    patchJSONResult<User>("/api/v1/auth/me", patch),
  changeMyPassword: (currentPassword: string, newPassword: string) =>
    postJSONResult<{ status: string }>("/api/v1/auth/me/password", {
      currentPassword,
      newPassword,
    } as ChangePasswordRequest),
  startMFAEnrollment: () =>
    postJSONResult<MFAEnrollResponse>("/api/v1/auth/me/mfa/enroll", {}),
  enableMFA: (challengeToken: string, code: string) =>
    postJSONResult<{ status: string }>("/api/v1/auth/me/mfa/enable", {
      challengeToken,
      code,
    }),
  disableMFA: (currentPassword: string, code: string) =>
    postJSONResult<{ status: string }>("/api/v1/auth/me/mfa/disable", {
      currentPassword,
      code,
    } as MFADisableRequest),

  listUsers: () => getJSON<User[]>("/api/v1/users"),
  createUser: (u: Omit<User, "id"> & { password: string }) =>
    postJSONResult<User>("/api/v1/users", u),
  updateUser: (id: string, patch: Partial<User>) =>
    patchJSONResult<User>(`/api/v1/users/${encodeURIComponent(id)}`, patch),
  setUserPassword: (id: string, password: string) =>
    postJSONResult<{ status: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/password`,
      { password },
    ),
  disableUserMFA: (id: string) =>
    postJSONResult<{ status: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/mfa/disable`,
      {},
    ),
  requireUserMFA: (id: string) =>
    postJSONResult<{ status: string; graceUntil?: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/mfa/require`,
      {},
    ),
  clearUserMFARequirement: (id: string) =>
    postJSONResult<{ status: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/mfa/clear`,
      {},
    ),
  extendUserMFAGrace: (id: string) =>
    postJSONResult<{ status: string; graceUntil?: string }>(
      `/api/v1/users/${encodeURIComponent(id)}/mfa/grace`,
      {},
    ),
  deleteUser: (id: string) =>
    deleteJSONResult(`/api/v1/users/${encodeURIComponent(id)}`),
};
