export const CONFIG_STAGED = "containd:config:staged";
export const CONFIG_COMMITTED = "containd:config:committed";

/** Explicit config inventory: operational POSTs must never invalidate candidate editors. */
export function configMutationEvent(path: string, method: string, payload?: unknown): string | null {
  if (!["POST", "PATCH", "DELETE"].includes(method)) return null;
  const route = path.split("?")[0].replace(/^\/api\/v1/, "");
  if (method === "POST" && /^\/config\/(commit|commit_confirmed|rollback)$/.test(route)) {
    return CONFIG_COMMITTED;
  }
  if (route === "/templates/ics/apply") {
    return method === "POST" && !(payload as { preview?: boolean } | undefined)?.preview
      ? CONFIG_STAGED : null;
  }
  if (route === "/templates/apply") return method === "POST" ? CONFIG_STAGED : null;
  if (route === "/firewall/rules/preview") return null;
  const object = /^\/(zones|assets|objects|firewall\/rules|firewall\/ics-rules)(\/[^/]+)?$/;
  const setting = /^\/(config|config\/candidate|config\/import|firewall\/nat|interfaces|interfaces\/assign|routing|ids\/rules|ids\/import|ids\/restore|dataplane|pcap\/config|services\/(syslog|dns|ntp|av|dhcp|proxy\/forward|proxy\/reverse|vpn|vpn\/openvpn\/profile)|learn\/apply)$/;
  const iface = /^\/interfaces\/[^/]+$/;
  if (route === "/interfaces/reconcile" || route === "/interfaces/state") return null;
  return object.test(route) || setting.test(route) || iface.test(route) ? CONFIG_STAGED : null;
}

/** Shared emit point for typed requests and successful multipart/raw callers. */
export function notifyConfigMutation(path: string, method: string, payload?: unknown) {
  const event = configMutationEvent(path, method, payload);
  if (event && typeof window !== "undefined") window.dispatchEvent(new CustomEvent(event));
}

export function subscribeConfigChanges(refresh: () => void): () => void {
  window.addEventListener(CONFIG_STAGED, refresh);
  window.addEventListener(CONFIG_COMMITTED, refresh);
  return () => {
    window.removeEventListener(CONFIG_STAGED, refresh);
    window.removeEventListener(CONFIG_COMMITTED, refresh);
  };
}
