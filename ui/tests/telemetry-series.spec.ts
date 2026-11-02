import { expect, test, type Page } from "@playwright/test";
import { decimalCounter, parseSeries, pointRate, responsePoints, sumPoints } from "../lib/api-telemetry";
import { seriesResponse, type WireResponse } from "./fixtures/telemetry";

type Scenario = { mutate?: (body: WireResponse, url: URL) => void; status?: number };
async function open(page: Page, scenario: Scenario = {}, path = "/system/services/dns/") {
  const requests: URL[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url());
    let body: unknown = {};
    let status = 200;
    if (url.pathname.includes("/auth/")) body = { id: "admin", username: "admin", role: "admin" };
    if (url.pathname === "/api/v1/telemetry/series") {
      requests.push(url);
      const data = seriesResponse(url, [20, 0, 10]);
      scenario.mutate?.(data, url);
      status = scenario.status ?? 200;
      body = status === 503 ? { error: "telemetry store offline" } : data;
    }
    if (url.pathname === "/api/v1/services/status") body = { faults: [], av: { available: false, error: "offline" }, dns: { enabled: true, running: true, installed: true, count: 12, errors_count: 0 } };
    if (url.pathname === "/api/v1/events" || url.pathname === "/api/v1/flows") body = [];
    await route.fulfill({ status, json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse(r => r.url().includes("/telemetry/series?"));
  await page.goto(path);
  await loaded;
  return requests;
}
const chart = (page: Page) => page.locator('[data-telemetry="DNS events per minute"]');

test("gaps are breaks, observed zero has no height floor, and a reset is marked", async ({ page }) => {
  await open(page, { mutate: body => {
    const points = body.series[0].points;
    points.at(-3)!.q = "reset";
    points.at(-1)!.q = "partial";
    points.at(-1)!.d = 20;
  } });
  const history = chart(page);
  await expect(history.locator('[data-quality="gap"]')).toHaveCount(357);
  await expect(history.locator('[data-quality="observed"][data-value="0"]')).toHaveCount(1);
  expect((await history.locator('[data-value="0"] [data-bar]').boundingBox())!.height).toBe(0);
  await expect(history.locator('[data-quality="gap"] [data-bar]')).toHaveCount(0);
  await expect(history.locator('[data-quality="reset"]')).toContainText("◆");
  await expect(history.locator('[data-quality="reset"]')).toHaveAttribute("aria-label", /Counter reset/);
  await expect(history.locator('[data-quality="partial"]')).toHaveAttribute("aria-label", /Partial bucket/);
  await expect(history.locator('[data-quality="partial"] [data-bar]')).toHaveCSS("border-style", "dashed");
  await expect(history).toContainText("Rate: 30.0 /min"); // 10 / 20 seconds, not 10 / 10.
});

test("the latest gap is unavailable, never the previous bucket's rate or a zero", async ({ page }) => {
  await open(page, { mutate: body => { const p = body.series[0].points.at(-1)!; delete p.v; delete p.d; p.q = "gap"; } });
  await expect(chart(page)).toContainText("Telemetry unavailable: latest real bucket is a gap");
  await expect(chart(page)).not.toContainText("Rate: 60.0");
  await expect(chart(page)).not.toContainText("Rate: 0.0");
  await expect(chart(page).getByRole("img")).toHaveCount(0);
});

test("a partial error count without duration remains visible without an invented rate", async ({ page }) => {
  await open(page, { mutate: body => {
    if (body.metric === "service.errors") {
      const last = body.series[0].points.at(-1)!;
      last.q = "partial";
      delete last.d;
    }
  } });
  await expect(page.getByText("Errors:", { exact: false })).toContainText("Errors: Unknown /min(Partial bucket · Count: 10; rate unavailable)");
});

for (const state of ["stalled", "unavailable"] as const) {
  test(`collector ${state} is visible and cannot fall back to demo`, async ({ page }) => {
    const requests = await open(page, { mutate: body => {
      body.realActive = false;
      body.collector.state = state;
      body.collector.error = "sample write failed";
    } });
    await expect(chart(page)).toContainText(`Collector ${state}: sample write failed`);
    await expect(page.getByText("Demo data", { exact: true })).toHaveCount(0);
    expect(requests.every(url => url.searchParams.get("origin") === "real")).toBe(true);
    await expect(chart(page).getByRole("img")).toHaveCount(0);
  });
}

test("503 reports unavailable with the API error, never zero or demo", async ({ page }) => {
  await open(page, { status: 503 });
  await expect(chart(page)).toContainText("Telemetry unavailable: telemetry store offline");
  await expect(chart(page).getByRole("img")).toHaveCount(0);
  await expect(page.getByText("Demo data", { exact: true })).toHaveCount(0);
});

test("a failed refresh clears a previously successful chart and recovers", async ({ page }) => {
  await page.clock.install();
  const scenario: Scenario = {};
  await open(page, scenario);
  await expect(chart(page).getByRole("img")).toBeVisible();
  scenario.status = 503;
  await page.clock.fastForward(10_000);
  await expect(chart(page)).toContainText("telemetry store offline");
  await expect(chart(page).getByRole("img")).toHaveCount(0);
  scenario.status = 200;
  await page.clock.fastForward(10_000);
  await expect(chart(page).getByRole("img")).toBeVisible();
  await expect(chart(page)).not.toContainText("unavailable");
});

test("covered quiet charts use explicitly labelled demo data only until real activity exists", async ({ page }) => {
  await page.clock.install();
  let active = false;
  const requests = await open(page, { mutate: (body, url) => {
    body.realActive = active;
    if (!active && url.searchParams.get("origin") === "real") {
      body.series = seriesResponse(url, [0, 0, 0]).series;
    }
  } });
  await expect(chart(page).getByText("Demo data", { exact: true })).toBeVisible();
  expect(requests.some(url => url.searchParams.get("origin") === "demo")).toBe(true);
  active = true;
  await page.clock.fastForward(10_000);
  await expect(chart(page).getByText("Demo data", { exact: true })).toHaveCount(0);
  await expect(chart(page).getByRole("img")).toBeVisible();
});

test("old demo history with a latest gap cannot replace covered quiet real data", async ({ page }) => {
  const requests = await open(page, { mutate: (body, url) => {
    body.realActive = false;
    body.series = seriesResponse(url, body.origin === "real" ? [0, 0, 0] : [5, 5, null]).series;
  } });
  await expect(chart(page)).toContainText("Rate: 0.0 /min");
  await expect(chart(page).getByText("Demo data", { exact: true })).toHaveCount(0);
  await expect(chart(page).locator('[data-quality="observed"][data-value="0"]')).toHaveCount(3);
  expect(requests.some(url => url.searchParams.get("origin") === "demo")).toBe(true);
});

for (const active of [false, true]) {
  test(`current unavailable sources keep real history and show all reasons (realActive=${active})`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    const requests = await open(page, { mutate: body => {
      body.realActive = active;
      body.collector.unavailable = [
        { source: "service", metric: body.metric, dims: { service: "dns" }, reason: "enforcement disabled" },
        { source: "engine", reason: "engine connection refused" },
      ];
    } });
    const reason = "Telemetry unavailable: enforcement disabled; engine connection refused";
    await expect(chart(page).getByRole("status")).toHaveText(reason);
    await expect(chart(page).getByRole("img")).toBeVisible();
    await expect(chart(page).locator('[data-value="20"]')).toHaveCount(1);
    await expect(chart(page)).toContainText("Rate: Unknown /min");
    await expect(page.getByText("Errors:", { exact: false })).toContainText(`Errors: Unknown /min${reason}`);
    await expect(page.getByText("Demo data", { exact: true })).toHaveCount(0);
    expect(requests.every(url => url.searchParams.get("origin") === "real")).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  });
}

test("a current source failure discovered during demo loading preserves real history instead", async ({ page }) => {
  await open(page, { mutate: body => {
    body.realActive = false;
    if (body.origin === "demo") body.collector.unavailable = [{ source: "engine", reason: "engine went offline" }];
  } });
  await expect(chart(page)).toContainText("Telemetry unavailable: engine went offline");
  await expect(chart(page).getByRole("img")).toBeVisible();
  await expect(chart(page).getByText("Demo data", { exact: true })).toHaveCount(0);
});

test("a running collector with no real activity cannot mask the latest real gap with demo", async ({ page }) => {
  await page.clock.install();
  let gap = false;
  const requests = await open(page, { mutate: (body, url) => {
    body.realActive = false;
    if (url.searchParams.get("origin") === "real") body.series = seriesResponse(url, gap ? [0, 0, null] : [0, 0, 0]).series;
  } });
  await expect(chart(page).getByText("Demo data", { exact: true })).toBeVisible();
  const demoReads = requests.filter(url => url.searchParams.get("origin") === "demo").length;
  gap = true;
  await page.clock.fastForward(10_000);
  await expect(chart(page)).toContainText("Telemetry unavailable: latest real bucket is a gap");
  await expect(chart(page).getByRole("img")).toHaveCount(0);
  await expect(page.getByText("Demo data", { exact: true })).toHaveCount(0);
  expect(requests.filter(url => url.searchParams.get("origin") === "demo")).toHaveLength(demoReads);
  gap = false;
  await page.clock.fastForward(10_000);
  await expect(chart(page).getByText("Demo data", { exact: true })).toBeVisible();
});

test("a collector outage found during the demo read outranks fallback", async ({ page }) => {
  await open(page, { mutate: (body, url) => {
    body.realActive = false;
    if (url.searchParams.get("origin") === "real") body.series = seriesResponse(url, [0]).series;
    else body.collector.state = "unavailable";
  } });
  await expect(chart(page)).toContainText("Collector unavailable");
  await expect(page.getByText("Demo data", { exact: true })).toHaveCount(0);
});

test("without real or demo history, show the honest first-run empty state", async ({ page }) => {
  const requests = await open(page, { mutate: body => { body.realActive = false; body.realCovered = false; body.series = []; } });
  await expect(chart(page)).toContainText("No traffic recorded yet");
  await expect(chart(page).getByRole("img")).toHaveCount(0);
  expect(requests.every(url => url.searchParams.get("origin") === "real")).toBe(true);
});

test("a previously active metric with no coverage does not claim a fresh install or zero", async ({ page }) => {
  await open(page, { mutate: body => { body.series = []; } });
  await expect(chart(page)).toContainText("No observed coverage in this range");
});

for (const range of ["24h", "30d"] as const) {
  test(`range selector requests retained ${range} history and rates at its resolution`, async ({ page }) => {
    const requests = await open(page);
    await expect(chart(page).getByRole("img")).toBeVisible();
    const loaded = page.waitForResponse(r => r.url().includes("/telemetry/series?") && new URL(r.url()).searchParams.get("range") === range);
    await page.getByRole("combobox", { name: "DNS events per minute range" }).selectOption(range);
    await loaded;
    await expect(chart(page)).toContainText(`Rate: ${range === "24h" ? "10.0" : "0.7"} /min`);
    expect(requests.some(url => url.searchParams.get("range") === range && url.searchParams.get("metric") === "service.events")).toBe(true);
    await expect.poll(() => requests.some(url => url.searchParams.get("range") === range && url.searchParams.get("metric") === "service.errors")).toBe(true);
  });
}

test("retained history fits 390px without page-level horizontal scrolling", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page);
  await expect(chart(page).getByRole("img")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.screenshot({ path: testInfo.outputPath("telemetry-390.png"), fullPage: true });
});

test("wire parser preserves uint64 exactly and rejects overflow, numbers, invalid durations and missing buckets", () => {
  const url = new URL("http://localhost/api/v1/telemetry/series?metric=service.events&service=dns&range=1h&origin=real");
  const body = seriesResponse(url, [1]);
  body.series[0].points.at(-1)!.v = "18446744073709551615";
  expect(parseSeries(body).series[0].points.at(-1)!.v?.toString()).toBe("18446744073709551615");
  for (const value of ["18446744073709551616", "-1", "1.5", "01", 5]) expect(() => decimalCounter(value)).toThrow();
  body.series[0].points.at(-1)!.d = 0;
  expect(() => parseSeries(body)).toThrow("duration");
  body.series[0].points.at(-1)!.d = 10;
  body.series[0].points.pop();
  expect(() => parseSeries(body)).toThrow("Incomplete telemetry buckets");
});

test("collector unavailable metadata is optional but strictly validated when present", () => {
  const body = seriesResponse(new URL("http://localhost/api/v1/telemetry/series?metric=service.events&range=1h&origin=real"));
  expect(parseSeries(body).collector.unavailable).toBeUndefined();
  body.collector.unavailable = [];
  expect(parseSeries(body).collector.unavailable).toEqual([]);
  body.collector.unavailable = [
    { source: "engine", reason: "connection refused" },
    { source: "service", metric: "service.events", dims: { service: "dns" }, reason: "meter unavailable" },
  ];
  expect(parseSeries(body).collector.unavailable).toEqual(body.collector.unavailable);
  for (const unavailable of [
    null, {}, "offline", [null], [{}],
    [{ source: 1, reason: "offline" }], [{ source: "engine" }], [{ source: "engine", reason: 1 }],
    [{ source: "service", reason: "offline", metric: "unknown" }],
    [{ source: "service", reason: "offline", metric: 1 }],
    [{ source: "service", reason: "offline", metric: "toString" }],
    [{ source: "service", reason: "offline", dims: [] }],
    [{ source: "service", reason: "offline", dims: null }],
    [{ source: "service", reason: "offline", dims: { service: 1 } }],
  ]) {
    expect(() => parseSeries({ ...body, collector: { ...body.collector, unavailable } })).toThrow("Malformed collector unavailable metadata");
  }
});

test("aggregates both event sources without converting missing coverage to zero", () => {
  const t = "2026-11-02T12:00:00Z";
  const observed = { t, v: BigInt(0), d: 10, q: "observed" as const };
  expect(sumPoints([{ dims: { source: "engine" }, points: [observed] }, { dims: { source: "services" }, points: [{ t, q: "gap" }] }])[0]).toEqual({ t, v: BigInt(0), d: 10, q: "partial" });
  expect(() => sumPoints([{ dims: {}, points: [{ ...observed, v: BigInt("18446744073709551615") }] }, { dims: {}, points: [{ ...observed, v: BigInt(1) }] }])).toThrow("overflow");
});

test("grouped partial counts can omit duration, but observed and reset buckets cannot", () => {
  const url = new URL("http://localhost/api/v1/telemetry/series?metric=iface.rx_bytes&group=role&role=leaf&range=1h&origin=real");
  const body = seriesResponse(url, [10]);
  const last = body.series[0].points.at(-1)!;
  last.q = "partial";
  delete last.d;
  const parsed = parseSeries(body).series[0].points.at(-1)!;
  expect(parsed).toEqual({ t: last.t, q: "partial", v: BigInt(10) });
  expect(pointRate(parsed)).toBeNull();
  expect(pointRate(parsed, true)).toBeNull();
  for (const q of ["observed", "reset"] as const) {
    last.q = q;
    expect(() => parseSeries(body)).toThrow("duration");
  }
});

test("summing members with different or unknown durations retains only a partial count", () => {
  const t = "2026-11-02T12:00:00Z";
  const first = { dims: {}, points: [{ t, q: "observed" as const, v: BigInt(10), d: 10 }] };
  const second = { dims: {}, points: [{ t, q: "reset" as const, v: BigInt(20), d: 20 }] };
  const combined = sumPoints([first, second])[0];
  expect(combined).toEqual({ t, q: "partial", v: BigInt(30) });
  expect(pointRate(combined)).toBeNull();
  expect(sumPoints([first, { dims: {}, points: [combined] }])[0]).toEqual({ t, q: "partial", v: BigInt(40) });
  second.points[0].d = 10;
  const sameDuration = sumPoints([first, second])[0];
  expect(sameDuration).toEqual({ t, q: "reset", v: BigInt(30), d: 10 });
  expect(pointRate(sameDuration, true)).toBe(180);
});


test("a missing metric in a combined zone chart is partial, never a complete zero contribution", () => {
  const url = new URL("http://localhost/api/v1/telemetry/series?metric=iface.rx_bytes&group=zone&range=1h&origin=real");
  const rx = parseSeries(seriesResponse(url, [0]));
  url.searchParams.set("metric", "iface.tx_bytes");
  const tx = parseSeries(seriesResponse(url, []));
  expect(responsePoints([rx, tx]).at(-1)).toEqual({ ...rx.series[0].points.at(-1), q: "partial" });
});

test("collector failure notices wrap at 390px without hiding the fault", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const message = `store-write-failed-${"x".repeat(200)}`;
  await open(page, { mutate: body => { body.collector.state = "stalled"; body.collector.error = message; } });
  await expect(chart(page)).toContainText(`Collector stalled: ${message}`);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});
