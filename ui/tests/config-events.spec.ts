import { expect, test } from "@playwright/test";
import { policyAPI } from "../lib/api-policy";
import { servicesAPI } from "../lib/api-services";
import { uploadPcap } from "../lib/api-pcap";
import { CONFIG_COMMITTED, CONFIG_STAGED, notifyConfigMutation, subscribeConfigChanges } from "../lib/config-events";
import { deleteJSON, deleteJSONResult, patchJSON, patchJSONResult, postJSON, postJSONResult } from "../lib/api-request";

async function withBrowser(run: (target: EventTarget) => Promise<void>) {
  const previousWindow = globalThis.window;
  const previousFetch = globalThis.fetch;
  const target = Object.assign(new EventTarget(), { location: { pathname: "/" } });
  Object.defineProperty(globalThis, "window", { configurable: true, value: target });
  try { await run(target); }
  finally {
    globalThis.fetch = previousFetch;
    Object.defineProperty(globalThis, "window", { configurable: true, value: previousWindow });
  }
}

function response(state?: string, status = 204) {
  return new Response(null, { status, headers: state ? { "X-Containd-Config": state } : {} });
}

test("only successful responses with a recognized server header emit the matching event", async () => {
  await withBrowser(async (target) => {
    const events: string[] = [];
    for (const type of [CONFIG_STAGED, CONFIG_COMMITTED]) target.addEventListener(type, (event) => events.push(event.type));
    notifyConfigMutation(response("staged"));
    notifyConfigMutation(response("committed"));
    expect(events).toEqual([CONFIG_STAGED, CONFIG_COMMITTED]);
    for (const res of [response(), response("unknown"), response("staged", 400), response("committed", 500)]) notifyConfigMutation(res);
    expect(events).toEqual([CONFIG_STAGED, CONFIG_COMMITTED]);
  });
});

for (const [name, mutate] of Object.entries({
  postJSON: () => postJSON("/api/v1/zones", {}),
  patchJSON: () => patchJSON("/api/v1/zones/lan", {}),
  deleteJSON: () => deleteJSON("/api/v1/zones/lan"),
  postJSONResult: () => postJSONResult("/api/v1/zones", {}),
  patchJSONResult: () => patchJSONResult("/api/v1/zones/lan", {}),
  deleteJSONResult: () => deleteJSONResult("/api/v1/zones/lan"),
})) {
  test(`${name} trusts response headers without a route fallback and subscriptions clean up`, async () => {
    await withBrowser(async (target) => {
      let count = 0;
      const unsubscribe = subscribeConfigChanges(() => count++);
      try {
        globalThis.fetch = async () => response();
        await mutate();
        expect(count).toBe(0);
        globalThis.fetch = async () => response("staged");
        await mutate();
        expect(count).toBe(1);
        globalThis.fetch = async () => response("committed");
        await mutate();
        expect(count).toBe(2);
        globalThis.fetch = async () => new Response('{"error":"rejected"}', { status: 400, headers: { "X-Containd-Config": "staged" } });
        await mutate();
        expect(count).toBe(2);
        globalThis.fetch = async () => { throw new Error("offline"); };
        await mutate();
        expect(count).toBe(2);
        unsubscribe();
        target.dispatchEvent(new CustomEvent(CONFIG_COMMITTED));
        target.dispatchEvent(new CustomEvent(CONFIG_STAGED));
        expect(count).toBe(2);
      } finally { unsubscribe(); }
    });
  });
}

for (const [name, mutate] of Object.entries({
  importIDSRules: () => policyAPI.importIDSRules(new File(["[]"], "rules.json")),
  uploadAVDef: () => servicesAPI.uploadAVDef(new File(["definition"], "definition.ndb")),
  deleteAVDef: () => servicesAPI.deleteAVDef("definition.ndb"),
  uploadPcap: () => uploadPcap(new File(["capture"], "capture.pcap")),
})) {
  test(`${name} passes its raw multipart response to the shared notifier`, async () => {
    await withBrowser(async () => {
      let count = 0;
      const unsubscribe = subscribeConfigChanges(() => count++);
      try {
        globalThis.fetch = async () => new Response("{}", { headers: { "X-Containd-Config": "staged" } });
        expect((await mutate()).ok).toBe(true);
        expect(count).toBe(1);
        globalThis.fetch = async () => new Response("{}");
        expect((await mutate()).ok).toBe(true);
        expect(count).toBe(1);
        globalThis.fetch = async () => new Response('{"error":"rejected"}', { status: 400, headers: { "X-Containd-Config": "staged" } });
        expect((await mutate()).ok).toBe(false);
        expect(count).toBe(1);
      } finally { unsubscribe(); }
    });
  });
}

test("successful operational POST without the config header emits nothing", async () => {
  await withBrowser(async () => {
    let count = 0;
    const unsubscribe = subscribeConfigChanges(() => count++);
    try {
      globalThis.fetch = async (path, init) => {
        expect(path).toBe("/api/v1/pcap/start");
        expect(init?.method).toBe("POST");
        return new Response('{"running":true}');
      };
      expect((await postJSONResult("/api/v1/pcap/start", {})).ok).toBe(true);
      expect(count).toBe(0);
    } finally { unsubscribe(); }
  });
});
