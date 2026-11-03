import type { ApiResult } from "./api";
import { isRecord, postJSONResult } from "./api-request";
import { isProtectionToken, isProtectionStatus, type ProtectionStatus } from "./api-protection";

export type RuntimeApplyResult = {
  status: string; runningRevision: string; applyId: string; protection: ProtectionStatus;
};
export type FactoryResetResult = RuntimeApplyResult & { message: string; loggedOut: boolean; warnings: string[] };

export function isRuntimeApplyResult(value: unknown): value is RuntimeApplyResult {
  return isRecord(value) && typeof value.status === "string"
    && isProtectionToken(value.runningRevision)
    && isProtectionToken(value.applyId)
    && isProtectionStatus(value.protection);
}

export function isFactoryResetResult(value: unknown): value is FactoryResetResult {
  return isRecord(value) && typeof value.message === "string"
    && typeof value.loggedOut === "boolean" && Array.isArray(value.warnings) && value.warnings.every((w: unknown) => typeof w === "string") && isRuntimeApplyResult(value);
}

export async function postRuntimeResult<T extends RuntimeApplyResult>(
  path: string, payload: unknown, expectedRevision: string, validate: (value: unknown) => value is T,
): Promise<ApiResult<T>> {
  const result = await postJSONResult<unknown>(path, payload, expectedRevision);
  if (!result.ok) return result;
  return validate(result.data) ? { ...result, data: result.data }
    : { ok: false, error: "Configuration response could not be verified. Refresh configuration and protection status.", revision: result.revision };
}
