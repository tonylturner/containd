import { expect, test } from "@playwright/test";

// Flow summaries carry the sorted TAG labels their events carry.

const flows = [
  {
    flowId: "flow-tagged-0001", firstSeen: "2026-10-26T08:00:00Z", lastSeen: "2026-10-26T08:05:00Z",
    srcIp: "172.16.5.40", srcPort: 51512, dstIp: "10.20.0.7", dstPort: 22, transport: "tcp", application: "ssh",
    eventCount: 12, tags: ["ot.vendor", "vendor-access"],
  },
  {
    flowId: "flow-plain-0002", firstSeen: "2026-10-26T08:01:00Z", lastSeen: "2026-10-26T08:02:00Z",
    srcIp: "10.10.0.22", srcPort: 40110, dstIp: "10.20.0.5", dstPort: 502, transport: "tcp", application: "modbus",
    eventCount: 3,
  },
];

test("flows show the TAG labels that matched them", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/flows" ? flows
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.goto("/flows/");
  await loaded;
  await expect(page.getByRole("columnheader", { name: "Tags" })).toBeVisible();
  const row = (app: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name: app, exact: true }) });
  await expect(row("ssh")).toContainText("ot.vendor");
  await expect(row("ssh")).toContainText("vendor-access");
  await expect(row("modbus").getByRole("cell").nth(3)).toHaveText("—");
  expect(errors).toEqual([]);
});

test("flows show loading until the first answer, and polls keep the rows", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.clock.install();
  let calls = 0;
  let release: () => void = () => {};
  let gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/flows") {
      calls++;
      await gate;
      await route.fulfill({ json: calls === 1 ? flows : flows.slice(0, 1) });
      return;
    }
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body });
  });
  const flowsAnswer = () => page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/flows");

  const first = page.waitForRequest((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.goto("/flows/");
  await first;
  await expect(page.locator("main .animate-pulse").first()).toBeVisible();
  await expect(page.getByText("No flows yet", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Total flows: 0", { exact: true })).toHaveCount(0);

  let answered = flowsAnswer();
  release();
  await answered;
  await expect(page.getByText("Showing 2 of 2 flows", { exact: true })).toBeVisible();

  // Hold the poll: the rows and footer stay while it runs.
  gate = new Promise<void>((resolve) => { release = resolve; });
  const poll = page.waitForRequest((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.clock.runFor(10_000);
  await poll;
  await expect(page.getByRole("cell", { name: "ssh", exact: true })).toBeVisible();
  await expect(page.getByText("Showing 2 of 2 flows", { exact: true })).toBeVisible();
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);

  answered = flowsAnswer();
  release();
  await answered;
  await expect(page.getByText("Showing 1 of 1 flows", { exact: true })).toBeVisible();
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  expect(errors).toEqual([]);
});
