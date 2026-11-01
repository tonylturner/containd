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
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.goto("/flows/");
  await loaded;
  await expect(page.getByRole("columnheader", { name: "Tags" })).toHaveCount(0);
  const row = (app: string) => page.getByRole("row").filter({ has: page.getByText(`${app} · port`, { exact: true }) });
  await expect(row("ssh")).toContainText("Tags: 2");
  const inspect = row("ssh").getByRole("button", { name: "Inspect flow" });
  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await expect(inspect).toBeFocused();
  const detail = page.locator(`[id="${await inspect.getAttribute("aria-controls")}"]`);
  await expect(detail).toContainText("flow-tagged-0001");
  await expect(detail.getByText("ot.vendor", { exact: true })).toBeVisible();
  await expect(detail.getByText("vendor-access", { exact: true })).toBeVisible();
  await expect(detail.getByText("First Seen", { exact: true })).toBeVisible();
  await expect(detail).toContainText(new Date(flows[0].firstSeen).toLocaleString());
  await page.keyboard.press("Space");
  await expect(detail).toBeHidden();
  const plain = row("modbus").getByRole("button", { name: "Inspect flow" });
  await plain.click();
  await expect(page.locator(`[id="${await plain.getAttribute("aria-controls")}"]`).getByText("Tags", { exact: true }).locator("..")).toHaveText("Tags—");
  expect(errors).toEqual([]);
});

test("flows show loading until the first answer, and polls keep the rows", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.clock.install();
  let reply = flows;
  let release: () => void = () => {};
  let gate = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/flows") {
      // Strict Mode can issue multiple mount reads. Every read in the initial
      // phase gets the same snapshot; only the subsequent poll changes it.
      const snapshot = reply;
      await gate;
      await route.fulfill({ json: snapshot, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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
  reply = flows.slice(0, 1);
  gate = new Promise<void>((resolve) => { release = resolve; });
  const poll = page.waitForRequest((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.clock.runFor(10_000);
  await poll;
  await expect(page.getByText("ssh · port", { exact: true })).toBeVisible();
  await expect(page.getByText("Showing 2 of 2 flows", { exact: true })).toBeVisible();
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);

  answered = flowsAnswer();
  release();
  await answered;
  await expect(page.getByText("Showing 1 of 1 flows", { exact: true })).toBeVisible();
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  expect(errors).toEqual([]);
});
