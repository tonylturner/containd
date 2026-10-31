import { expect, test } from "@playwright/test";

import { cliWebSocketURL } from "../lib/api-core";
import { consoleAPI } from "../lib/api-console";

test("Console URLs carry only a ticket, under either runtime base path", () => {
  for (const pathname of ["/console/", "/containd/console/"]) {
    const url = new URL(cliWebSocketURL("one-use/ticket", "https:", "firewall.example", pathname));
    expect(url.protocol).toBe("wss:");
    expect(url.pathname).toBe(
      pathname.startsWith("/containd/") ? "/containd/api/v1/cli/ws" : "/api/v1/cli/ws",
    );
    expect([...url.searchParams.keys()]).toEqual(["ticket"]);
    expect(url.searchParams.get("ticket")).toBe("one-use/ticket");
    expect(url.searchParams.has("token")).toBe(false);
  }
  expect(cliWebSocketURL("fresh-ticket", "http:", "localhost", "/"))
    .toBe("ws://localhost/api/v1/cli/ws?ticket=fresh-ticket");
});

test("Console requests a fresh ticket each time using cookie auth and Bearer fallback", async () => {
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, "sessionStorage");
  const originalFetch = globalThis.fetch;
  const calls: { url: string; init: RequestInit }[] = [];
  let sequence = 0;
  Object.defineProperty(globalThis, "window", {
    configurable: true, value: { location: { pathname: "/containd/console/" } },
  });
  Object.defineProperty(globalThis, "sessionStorage", {
    configurable: true,
    value: { getItem: (key: string) => key === "containd.session.token" ? "session-jwt" : null },
  });
  globalThis.fetch = async (input, init) => {
    calls.push({ url: String(input), init: init ?? {} });
    if (calls.length === 2) {
      return new Response('{"error":"missing cookie"}', { status: 401 });
    }
    sequence += 1;
    return new Response(JSON.stringify({ ticket: `ticket-${sequence}`, expiresIn: 30 }), {
      status: 200, headers: { "Content-Type": "application/json" },
    });
  };
  try {
    const first = await consoleAPI.createCLIWebSocketTicket();
    const second = await consoleAPI.createCLIWebSocketTicket();
    expect(first?.ticket).toBe("ticket-1");
    expect(second?.ticket).toBe("ticket-2");
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      expect(call.url).toBe("/containd/api/v1/cli/ws/ticket");
      expect(call.url).not.toContain("session-jwt");
      expect(call.init.method).toBe("POST");
      expect(call.init.credentials).toBe("include");
    }
    expect(new Headers(calls[0].init.headers).has("Authorization")).toBe(false);
    expect(new Headers(calls[1].init.headers).has("Authorization")).toBe(false);
    expect(new Headers(calls[2].init.headers).get("Authorization")).toBe("Bearer session-jwt");
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
    if (originalStorage) Object.defineProperty(globalThis, "sessionStorage", originalStorage);
    else Reflect.deleteProperty(globalThis, "sessionStorage");
  }
});
