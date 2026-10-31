import { expect, test } from "@playwright/test";

import {
  apiURL,
  apiWebSocketURL,
  staticAssetURL,
} from "../lib/api-core";

test("static asset URLs stay under the runtime /containd base path", () => {
  const url = staticAssetURL("/icons/docker.svg", "/containd/topology/");

  expect(url).toBe("/containd/icons/docker.svg");
  expect(url).not.toMatch(/^\/icons\//);
});

test("static asset URLs remain root-relative when the UI is at the origin root", () => {
  expect(staticAssetURL("/icons/docker.svg", "/topology/")).toBe(
    "/icons/docker.svg",
  );
});

test("API URLs include the runtime base path", () => {
  expect(
    apiURL(
      "/api/v1/pcap/download/capture%20one.pcap",
      "/containd/pcap/",
    ),
  ).toBe("/containd/api/v1/pcap/download/capture%20one.pcap");
});

test("CLI WebSocket URLs include the base path and preserve page protocol", () => {
  expect(
    apiWebSocketURL(
      "/api/v1/cli/ws",
      "https:",
      "firewall.example",
      "/containd/console/",
    ),
  ).toBe("wss://firewall.example/containd/api/v1/cli/ws");
  expect(
    apiWebSocketURL("/api/v1/cli/ws", "http:", "firewall.example", "/"),
  ).toBe("ws://firewall.example/api/v1/cli/ws");
});

test("proxy-rewritten API literals receive exactly one runtime prefix", () => {
  // Apply the proxy's exact JavaScript sub_filter to the quoted literals.
  for (const literal of ['"/api/v1/cli/ws/ticket"', '"/api/v1/cli/ws"']) {
    const rewritten: string = JSON.parse(literal.replace('"/api/', '"/containd/api/'));
    const original: string = JSON.parse(literal);
    for (const pathname of ["/containd/", "/containd"]) {
      expect(apiURL(rewritten, pathname)).toBe(rewritten);
      expect(staticAssetURL(rewritten, pathname)).toBe(rewritten);
      expect(apiWebSocketURL(rewritten, "https:", "localhost:8088", pathname))
        .toBe(`wss://localhost:8088${rewritten}`);
      expect(apiURL(original, pathname)).toBe(rewritten);
    }
    expect(apiURL(original, "/")).toBe(original);
    expect(staticAssetURL(original, "/")).toBe(original);
    expect(apiWebSocketURL(original, "http:", "localhost:8088", "/"))
      .toBe(`ws://localhost:8088${original}`);
  }
  const asset: string = JSON.parse('"/_next/static/example.js"'
    .replace('"/_next/', '"/containd/_next/'));
  expect(staticAssetURL(asset, "/containd/")).toBe(asset);
});

test("URL prefix matching respects the complete base path boundary", () => {
  for (const path of ["/containd", "/containd/api/v1/health"]) {
    expect(apiURL(path, "/containd/")).toBe(path);
    expect(staticAssetURL(path, "/containd/")).toBe(path);
    expect(apiWebSocketURL(path, "http:", "localhost", "/containd/"))
      .toBe(`ws://localhost${path}`);
  }
  expect(apiURL("/containd-other/api", "/containd/"))
    .toBe("/containd/containd-other/api");
});
