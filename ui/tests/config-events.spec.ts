import { expect, test } from "@playwright/test";
import { policyAPI } from "../lib/api-policy";
import { CONFIG_COMMITTED, CONFIG_STAGED, configMutationEvent, subscribeConfigChanges } from "../lib/config-events";
import { deleteJSON, deleteJSONResult, patchJSON, patchJSONResult, postJSON, postJSONResult } from "../lib/api-request";

const staged = ["/firewall/rules", "/firewall/rules/r1", "/firewall/ics-rules/r1", "/assets/a", "/objects/o", "/zones/lan", "/interfaces", "/interfaces/lan", "/interfaces/assign", "/routing", "/firewall/nat", "/ids/rules", "/ids/import", "/ids/restore", "/dataplane", "/pcap/config", "/services/syslog", "/services/dns", "/services/ntp", "/services/av", "/services/dhcp", "/services/proxy/forward", "/services/proxy/reverse", "/services/vpn", "/services/vpn/openvpn/profile", "/config", "/config/candidate", "/config/import", "/templates/apply", "/templates/ics/apply", "/learn/apply"];

test("configuration inventory emits staged, GETs and previews do not", () => {
  for (const path of staged) {
    expect(configMutationEvent(`/api/v1${path}`, "POST", {}), path).toBe(CONFIG_STAGED);
    expect(configMutationEvent(`/api/v1${path}`, "GET"), path).toBeNull();
  }
  expect(configMutationEvent("/api/v1/templates/ics/apply", "POST", { preview: true })).toBeNull();
});

test("operational mutations never emit staged", () => {
  for (const path of ["/pcap/start", "/pcap/stop", "/pcap/tag", "/pcap/replay", "/pcap/upload", "/pcap/capture.pcap", "/pcap/analyze", "/dataplane/blocks/host", "/dataplane/blocks/flow", "/conntrack/kill", "/signatures", "/identities", "/services/vpn/openvpn/clients", "/services/av/update", "/services/av/defs", "/users", "/system/tls/cert", "/system/tls/trusted-ca", "/interfaces/reconcile", "/routing/reconcile", "/config/backups", "/config/backups/one", "/config/confirm", "/ids/convert/sigma", "/firewall/rules/preview", "/learn/generate", "/learn"]) {
    for (const method of ["POST", "PATCH", "DELETE"]) expect(configMutationEvent(`/api/v1${path}`, method), `${method} ${path}`).toBeNull();
  }
});

test("promotion and rollback emit committed, not staged", () => {
  for (const path of ["commit", "commit_confirmed", "rollback"]) expect(configMutationEvent(`/api/v1/config/${path}`, "POST")).toBe(CONFIG_COMMITTED);
});

for (const [name, mutate] of Object.entries({
  postJSON: () => postJSON("/api/v1/zones", {}),
  patchJSON: () => patchJSON("/api/v1/zones/lan", {}),
  deleteJSON: () => deleteJSON("/api/v1/zones/lan"),
  postJSONResult: () => postJSONResult("/api/v1/zones", {}),
  patchJSONResult: () => patchJSONResult("/api/v1/zones/lan", {}),
  deleteJSONResult: () => deleteJSONResult("/api/v1/zones/lan"),
})) {
  test(`${name} emits only on success and subscription cleans up both events`, async () => {
    const previousWindow = globalThis.window;
    const previousFetch = globalThis.fetch;
    const target = Object.assign(new EventTarget(), { location: { pathname: "/" } });
    Object.defineProperty(globalThis, "window", { configurable: true, value: target });
    let count = 0;
    const unsubscribe = subscribeConfigChanges(() => count++);
    try {
      globalThis.fetch = async () => new Response(null, { status: 204 });
      await mutate();
      expect(count).toBe(1);
      target.dispatchEvent(new CustomEvent(CONFIG_COMMITTED));
      expect(count).toBe(2);
      globalThis.fetch = async () => new Response('{"error":"rejected"}', { status: 400 });
      await mutate();
      expect(count).toBe(2);
      globalThis.fetch = async () => { throw new Error("offline"); };
      await mutate();
      expect(count).toBe(2);
      unsubscribe();
      target.dispatchEvent(new CustomEvent(CONFIG_COMMITTED));
      target.dispatchEvent(new CustomEvent(CONFIG_STAGED));
      expect(count).toBe(2);
    } finally {
      unsubscribe();
      globalThis.fetch = previousFetch;
      Object.defineProperty(globalThis, "window", { configurable: true, value: previousWindow });
    }
  });
}

test("multipart IDS imports join the same successful mutation mechanism", async () => {
  const previousWindow = globalThis.window;
  const previousFetch = globalThis.fetch;
  const target = Object.assign(new EventTarget(), { location: { pathname: "/" } });
  Object.defineProperty(globalThis, "window", { configurable: true, value: target });
  let count = 0;
  const unsubscribe = subscribeConfigChanges(() => count++);
  try {
    globalThis.fetch = async () => new Response('{"imported":1,"total":1,"skipped":0,"format":"json"}', { status: 200 });
    expect((await policyAPI.importIDSRules(new File(["[]"], "rules.json"))).ok).toBe(true);
    expect(count).toBe(1);
    globalThis.fetch = async () => new Response('{"error":"rejected"}', { status: 400 });
    expect((await policyAPI.importIDSRules(new File(["[]"], "rules.json"))).ok).toBe(false);
    expect(count).toBe(1);
  } finally {
    unsubscribe();
    globalThis.fetch = previousFetch;
    Object.defineProperty(globalThis, "window", { configurable: true, value: previousWindow });
  }
});
