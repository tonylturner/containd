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
