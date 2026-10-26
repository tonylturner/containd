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
  getJSONList,
  getJSONWithStatus,
  patchJSONResult,
  postJSON,
  postJSONResult,
} from "./api-request";

import type {
  ApiResult,
  ChangePasswordRequest,
  LoginResponse,
  LoginStartResponse,
  MFADisableRequest,
  MFAEnrollResponse,
  UpdateMeRequest,
  User,
} from "./api";

export const authAPI = {
  /** A failure carries the server's message, and Retry-After when rate limited. */
  login: async (username: string, password: string): Promise<ApiResult<LoginStartResponse>> => {
    const res = await postJSONResult<LoginStartResponse>("/api/v1/auth/login", {
      username,
      password,
    });
    if (!res.ok) return res;
    if ("token" in res.data && res.data.token) setSessionToken(res.data.token);
    if ("token" in res.data && res.data.user?.role) setStoredRole(res.data.user.role);
    clearAuthExpired();
    setLastAuthError(null);
    return res;
  },
  /** A failure carries the server's message, and Retry-After while the code check is locked. */
  verifyLoginMFA: async (challengeToken: string, code: string): Promise<ApiResult<LoginResponse>> => {
    const res = await postJSONResult<LoginResponse>("/api/v1/auth/login/mfa", {
      challengeToken,
      code,
    });
    if (!res.ok) return res;
    if (res.data.token) setSessionToken(res.data.token);
    if (res.data.user?.role) setStoredRole(res.data.user.role);
    clearAuthExpired();
    setLastAuthError(null);
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

  listUsers: () => getJSONList<User>("/api/v1/users"),
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
