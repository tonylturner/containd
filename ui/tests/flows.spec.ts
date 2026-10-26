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
