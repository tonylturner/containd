"use client";

import { useSyncExternalStore } from "react";
import {
  getServerStoredRoleSnapshot,
  getStoredRoleSnapshot,
  subscribeStoredRole,
} from "../lib/api-core";

/** Admin-only UI is hidden until the browser role has been read after mount. */
export function useIsAdmin(): boolean {
  return useSyncExternalStore(
    subscribeStoredRole,
    getStoredRoleSnapshot,
    getServerStoredRoleSnapshot,
  ) === "admin";
}
