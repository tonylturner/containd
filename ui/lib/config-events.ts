export const CONFIG_STAGED = "containd:config:staged";
export const CONFIG_COMMITTED = "containd:config:committed";

/** The successful response header is the sole authority for mutation events. */
export function notifyConfigMutation(response: Response) {
  if (!response.ok || typeof window === "undefined") return;
  const state = response.headers.get("X-Containd-Config");
  const event = state === "staged" ? CONFIG_STAGED : state === "committed" ? CONFIG_COMMITTED : null;
  if (event) window.dispatchEvent(new CustomEvent(event));
}

export function subscribeConfigChanges(refresh: () => void): () => void {
  window.addEventListener(CONFIG_STAGED, refresh);
  window.addEventListener(CONFIG_COMMITTED, refresh);
  return () => {
    window.removeEventListener(CONFIG_STAGED, refresh);
    window.removeEventListener(CONFIG_COMMITTED, refresh);
  };
}
