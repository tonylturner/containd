import { fetchWithSession } from "./api-core";
import {
  normalizeICSEnforcementHealth,
  type ICSEnforcementHealth,
} from "./api-ics-coverage";

// GET /api/v1/health: liveness plus runtime enforcement and recovery state.

/** Runtime IEC 104 enforcement health. `active` describes the loaded
 * runtime envelope, not the saved config. */
export type IEC104EnforcementHealth = {
  active: boolean;
  healthy: boolean;
  reason: string;
};

/**
 * Boot recovery from GET /health, with or without a reservation. Active means
 * the fail-closed recovery ruleset is applied (new transit dropped); pending
 * and failed mean it is not. The refusal itself is in the reservation view.
 */
export type ManagementRecoveryHealth = {
  state: "inactive" | "active" | "pending" | "failed" | "unknown";
  reason: string;
};

const RECOVERY_STATES: ReadonlySet<string> = new Set(["inactive", "active", "pending", "failed", "unknown"]);

/** An unrecognised state reads as unknown; a missing object as none. */
export function normalizeManagementRecovery(value: unknown): ManagementRecoveryHealth | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const { state, reason } = value as Record<string, unknown>;
  return {
    state: typeof state === "string" && RECOVERY_STATES.has(state) ? (state as ManagementRecoveryHealth["state"]) : "unknown",
    reason: typeof reason === "string" ? reason : "",
  };
}

/**
 * General firewall enforcement, apart from IEC 104. Degraded: a ruleset is in
 * force but the last apply failed, or the schedule planner is degraded.
 * Unavailable: no ruleset in force, or a persisted recovery fault.
 */
export type EnforcementHealth = {
  state: "enforcing" | "degraded" | "disabled" | "unavailable" | "unknown";
  reason: string;
};

const ENFORCEMENT_STATES: ReadonlySet<string> = new Set(["enforcing", "degraded", "disabled", "unavailable", "unknown"]);

/** An unrecognised state reads as unknown; a missing object as none. */
export function normalizeEnforcementHealth(value: unknown): EnforcementHealth | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const { state, reason } = value as Record<string, unknown>;
  return {
    state: typeof state === "string" && ENFORCEMENT_STATES.has(state) ? (state as EnforcementHealth["state"]) : "unknown",
    reason: typeof reason === "string" ? reason : "",
  };
}

export type HealthResponse = {
  status: string;
  component: string;
  build?: string;
  time?: string;
  enforcement?: EnforcementHealth;
  iec104Enforcement?: IEC104EnforcementHealth;
  icsEnforcement?: ICSEnforcementHealth;
  managementRecovery?: ManagementRecoveryHealth;
};

export async function fetchHealth(
  signal?: AbortSignal,
): Promise<HealthResponse | null> {
  try {
    const res = await fetchWithSession(
      "/api/v1/health",
      {
        cache: "no-store",
      },
      signal,
    );
    if (!res.ok) return null;
    const body = (await res.json()) as HealthResponse;
    return {
      ...body,
      enforcement: normalizeEnforcementHealth(body?.enforcement),
      icsEnforcement: normalizeICSEnforcementHealth(body?.icsEnforcement),
      managementRecovery: normalizeManagementRecovery(body?.managementRecovery),
    };
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    return null;
  }
}
