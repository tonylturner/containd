import type { ApiResult } from "./api";
import { authHeaders, clearAuthExpired, fetchWithSession, handleUnauthorized } from "./api-core";
import { isRecord, postJSONResult } from "./api-request";

export type ProtectionState = "pending" | "protecting" | "degraded" | "failed" | "disabled" | "unknown";
export type ProtectionAcknowledgement = {
  bootId: string; applyId: string; runningRevision: string;
  mode: "normal" | "recovery"; operation: "apply" | "stop"; trustRevision?: string;
};
export type ProtectionSubsystem = {
  name: string; owner: "engine" | "management"; desiredRevision: string;
  operation: "apply" | "stop" | ""; state: "ready" | "pending" | "failed" | "off" | "unknown";
  acknowledged: ProtectionAcknowledgement | null;
  fault: { kind: "config" | "render" | "delivery" | "unknown"; reason: string } | null;
  reason: string; attempt: number; nextRetryAt: string | null; observedAt: string;
  retryable: boolean; required: boolean; desiredTrustRevision?: string;
};
export type ProtectionComponent = {
  name: string; required: boolean; state: "ready" | "pending" | "failed" | "off";
  reason: string; attempt?: number; maxAttempts?: number; since: string;
};
export type ProtectionEffect = {
  traffic: string; effect: "normal" | "fail_closed_drop" | "not_inspected" | "unknown";
};
export type ProtectionStatus = {
  bootId: string; applyId: string; installedApplyId: string; runningRevision: string;
  mode: "normal" | "recovery" | ""; installed: ProtectionAcknowledgement | null;
  desiredRevision: string | null; appliedRevision: string | null; protectingRevision: string | null;
  ready: boolean; state: ProtectionState; retryable: boolean; observedAt: string;
  components: ProtectionComponent[]; effects: ProtectionEffect[]; subsystems: ProtectionSubsystem[];
};

const STATES = new Set(["pending", "protecting", "degraded", "failed", "disabled", "unknown"]);
const COMPONENT_STATES = new Set(["ready", "pending", "failed", "off"]);
const EFFECTS = new Set(["normal", "fail_closed_drop", "not_inspected", "unknown"]);
const count = (value: unknown) => Number.isInteger(value) && (value as number) >= 0;
const optionalCount = (value: unknown) => value === undefined || count(value);
export const isProtectionToken = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const nullableRevision = (value: unknown) => value === null || isProtectionToken(value);
const nullableString = (value: unknown) => value === null || typeof value === "string";
const optionalString = (value: unknown) => value === undefined || typeof value === "string";

export function isProtectionAcknowledgement(value: unknown): value is ProtectionAcknowledgement {
  return isRecord(value) && ["bootId", "applyId"].every(k => isProtectionToken(value[k]))
    && (value.mode === "normal" ? isProtectionToken(value.runningRevision) : value.runningRevision === `recovery:${value.bootId}`)
    && ["normal", "recovery"].includes(value.mode as string) && ["apply", "stop"].includes(value.operation as string)
    && optionalString(value.trustRevision);
}

export function isProtectionSubsystem(value: unknown): value is ProtectionSubsystem {
  return isRecord(value) && ["name", "desiredRevision", "reason", "observedAt"].every(k => typeof value[k] === "string")
    && ["engine", "management"].includes(value.owner as string)
    && ["apply", "stop", ""].includes(value.operation as string)
    && ["ready", "pending", "failed", "off", "unknown"].includes(value.state as string)
    && (value.acknowledged === null || isProtectionAcknowledgement(value.acknowledged))
    && (value.fault === null || (isRecord(value.fault) && ["config", "render", "delivery", "unknown"].includes(value.fault.kind as string)
      && typeof value.fault.reason === "string"))
    && count(value.attempt) && nullableString(value.nextRetryAt) && typeof value.retryable === "boolean"
    && typeof value.required === "boolean" && optionalString(value.desiredTrustRevision);
}

/** Old engine-only responses are unavailable, never normalized into readiness. */
export function isProtectionStatus(value: unknown): value is ProtectionStatus {
  if (!isRecord(value)) return false;
  return ["bootId", "applyId", "installedApplyId", "runningRevision", "observedAt"].every(k => typeof value[k] === "string")
    && ["normal", "recovery", ""].includes(value.mode as string)
    && (value.installed === null || isProtectionAcknowledgement(value.installed))
    && ["desiredRevision", "appliedRevision", "protectingRevision"].every(k => nullableRevision(value[k]))
    && typeof value.ready === "boolean" && STATES.has(value.state as string) && typeof value.retryable === "boolean"
    && (!value.ready || (value.state === "protecting" && value.mode === "normal" && !!value.bootId && !!value.applyId
      && !!value.desiredRevision && value.desiredRevision === value.runningRevision
      && value.desiredRevision === value.appliedRevision && value.desiredRevision === value.protectingRevision
      && isProtectionAcknowledgement(value.installed) && value.installed.bootId === value.bootId
      && value.installed.applyId === value.applyId && value.installed.runningRevision === value.desiredRevision
      && value.installed.mode === "normal" && value.installed.operation === "apply"))
    && Array.isArray(value.subsystems) && value.subsystems.every(isProtectionSubsystem)
    && Array.isArray(value.components) && value.components.every((c: unknown) =>
      isRecord(c) && typeof c.name === "string" && typeof c.required === "boolean"
      && COMPONENT_STATES.has(c.state as string) && typeof c.reason === "string" && typeof c.since === "string"
      && optionalCount(c.attempt) && optionalCount(c.maxAttempts))
    && Array.isArray(value.effects) && value.effects.every((e: unknown) =>
      isRecord(e) && typeof e.traffic === "string" && EFFECTS.has(e.effect as string));
}

export async function fetchProtection(signal?: AbortSignal): Promise<ProtectionStatus | undefined> {
  const res = await fetchWithSession("/api/v1/dataplane/protection", { headers: authHeaders(), cache: "no-store" }, signal);
  if (handleUnauthorized(res)) return undefined;
  clearAuthExpired();
  if (res.status !== 200 && res.status !== 502) return undefined;
  const body: unknown = await res.json().catch(() => undefined);
  // Collection failures can still carry useful owner faults, but never green.
  return isProtectionStatus(body) && (res.status === 200 || (!body.ready && body.state === "unknown")) ? body : undefined;
}

export async function retryProtection(observation: Pick<ProtectionStatus, "bootId" | "applyId" | "desiredRevision">): Promise<ApiResult<{ status: "retrying"; applyId: string; desiredRevision: string }>> {
  const result = await postJSONResult<unknown>("/api/v1/dataplane/protection/retry", {
    bootId: observation.bootId, applyId: observation.applyId, desiredRevision: observation.desiredRevision,
  });
  if (!result.ok) return result;
  const body = result.data;
  return isRecord(body) && body.status === "retrying" && body.applyId === observation.applyId
    && typeof body.desiredRevision === "string" && body.desiredRevision === observation.desiredRevision
    ? { ...result, data: { status: "retrying", applyId: observation.applyId, desiredRevision: body.desiredRevision } }
    : { ok: false, error: "Retry acceptance could not be verified. Refresh protection status." };
}
