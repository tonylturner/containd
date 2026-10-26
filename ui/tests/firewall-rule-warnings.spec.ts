import { expect, test, type Page } from "@playwright/test";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const scheduled = {
  id: "maint-allow", action: "ALLOW", sourceZones: ["it"], destZones: ["ot"],
  protocols: [{ name: "tcp", port: "22" }],
  schedule: { daysOfWeek: ["Saturday"], startTime: "02:00", endTime: "06:00" },
};
const warning = {
  ruleId: "maint-allow", predicate: "schedule", action: "ALLOW",
  message: "schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive",
};

async function openFirewall(page: Page, previews: unknown[]) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = [scheduled];
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    if (path === "/api/v1/dataplane/ruleset") {
      body = { ruleset: "table inet containd {}", runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" }, warnings: [warning] };
    }
    if (path === "/api/v1/firewall/rules/preview") {
      previews.push(request.postDataJSON());
      body = { match_count: 0, sample_matches: [], time_range: null, total_events: 12, warnings: [warning] };
    }
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/firewall/");
  await loaded;
}

test("rule impact preview explains an inactive scheduled ALLOW", async ({ page }) => {
  const previews: unknown[] = [];
  await openFirewall(page, previews);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByRole("button", { name: "Preview impact" }).click();
  const summary = page.getByLabel("Rule impact preview");
  await expect(summary).toContainText("0 of 12 recent events match this rule on its own.");
  await expect(summary.getByRole("status")).toContainText("maint-allow: schedules are enforced only on ICS rules inspected through NFQUEUE; ALLOW rule inactive");
  // The preview carries the schedule the form does not edit.
  expect(previews).toHaveLength(1);
  expect(previews[0]).toMatchObject({ id: "maint-allow", action: "ALLOW", schedule: scheduled.schedule });
});

test("ruleset preview lists candidate warnings", async ({ page }) => {
  await openFirewall(page, []);
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Rule predicates resolved toward denial" })).toContainText("maint-allow: schedules are enforced");
});
