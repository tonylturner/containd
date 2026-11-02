import { expect, test } from "@playwright/test";
import { readTelemetry } from "../hooks/useTelemetry";
import { seriesResponse, type WireResponse } from "./fixtures/telemetry";
import { validConduitTraffic } from "../lib/conduit-traffic";

for (const scenario of ["fresh", "gap", "unavailable", "realActive"] as const) {
  test(`telemetry reader precedence: ${scenario}`, async () => {
    const original = globalThis.fetch;
    const origins: string[] = [];
    globalThis.fetch = async input => {
      const url = new URL(String(input), "http://localhost");
      origins.push(url.searchParams.get("origin")!);
      const body: WireResponse = seriesResponse(url, [10, 20, 30]);
      body.realActive = scenario === "realActive";
      if (body.origin === "real") {
        if (scenario === "fresh") body.series = [];
        if (scenario === "gap") body.series = seriesResponse(url, [10, 20, null]).series;
        if (scenario === "unavailable") body.collector.unavailable = [{ source: "iface", reason: "statistics unreadable" }];
      }
      return Response.json(body);
    };
    try {
      const read = await readTelemetry([{ metric: "iface.rx_bytes" }], "1h");
      expect(read.demo).toBe(scenario === "fresh");
      expect(read.noCurrentData ?? false).toBe(scenario === "gap");
      expect(read.unavailable).toBe(scenario === "unavailable" ? "Telemetry unavailable: statistics unreadable" : undefined);
      expect(origins).toEqual(scenario === "fresh" ? ["real", "demo"] : ["real"]);
      if (scenario === "realActive") expect(read.data[0].origin).toBe("real");
    } finally {
      globalThis.fetch = original;
    }
  });
}

test("conduit demo and none shapes are distinct from measured and unavailable", () => {
  const demo = { state: "demo", coverage: "recorded", windowSeconds: 3600, packets: "20", bytes: "300", complete: true };
  expect(validConduitTraffic(demo)).toBe(true);
  expect(validConduitTraffic({ state: "none" })).toBe(true);
  expect(validConduitTraffic({ ...demo, coverage: "routed" })).toBe(false);
  expect(validConduitTraffic({ ...demo, state: "measured" })).toBe(false);
  expect(validConduitTraffic({ ...demo, packets: 20 })).toBe(false);
  expect(validConduitTraffic({ ...demo, bytes: "-1" })).toBe(false);
});
