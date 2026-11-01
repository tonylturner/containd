import { expect, test } from "@playwright/test";
import { failureOf, getConfigJSON, postJSONResult } from "../lib/api-request";

const revision = "0123456789abcdef.15";
for (const [status, code] of [[412, "config_revision_mismatch"], [428, "config_revision_required"], [400, "config_revision_malformed"]] as const) {
  test(`revision failure ${status} retains structured fields independently of message text`, async () => {
    const failure = await failureOf(new Response(JSON.stringify({ error: "arbitrary message", code, currentRevision: revision }), { status }));
    expect(failure).toMatchObject({ ok: false, status, code, currentRevision: revision, error: "arbitrary message" });
  });
}

test("config snapshots require a header and a mutation carries exactly the supplied base", async () => {
  const original = globalThis.fetch;
  const requests: RequestInit[] = [];
  let withHeader = true;
  globalThis.fetch = async (_url, init) => {
    requests.push(init ?? {});
    return new Response(JSON.stringify({ enabled: true }), { headers: withHeader ? { "X-Containd-Revision": revision } : {} });
  };
  try {
    expect(await getConfigJSON("/api/v1/services/dns")).toEqual({ data: { enabled: true }, revision });
    const result = await postJSONResult("/api/v1/services/dns", { enabled: true }, revision);
    expect(result).toMatchObject({ ok: true, data: { enabled: true }, revision });
    expect(new Headers(requests[1].headers).get("X-Containd-If-Revision")).toBe(revision);
    withHeader = false;
    expect(await getConfigJSON("/api/v1/services/dns")).toBeNull();
  } finally { globalThis.fetch = original; }
});

for (const body of [null, "not an object", 42]) {
  test(`malformed revision error body ${JSON.stringify(body)} retains its status`, async () => {
    const failure = await failureOf(new Response(JSON.stringify(body), { status: 412 }));
    expect(failure).toMatchObject({ ok: false, status: 412 });
    expect(failure.code).toBeUndefined();
  });
}
