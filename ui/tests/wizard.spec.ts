import { expect, test, type Page } from "@playwright/test";

// The publish-service wizard checks the server address and port on the step
// where they are typed, with the same rules it applies when staging the port
// forward. A port forward's destination must be IPv4.

const zones = [{ name: "wan" }, { name: "lan" }];

/** Mocks the wizard's API and records the staged NAT config. */
async function mockWizardAPI(page: Page) {
  const staged: unknown[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/api/v1/firewall/nat" && method === "POST") {
      const body = route.request().postDataJSON();
      staged.push(body);
      await route.fulfill({ json: body });
      return;
    }
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] }
        : path === "/api/v1/zones" ? zones
          : path === "/api/v1/firewall/nat" ? { enabled: false }
            : method === "POST" ? route.request().postDataJSON() : {};
    await route.fulfill({ json });
  });
  return staged;
}

async function openPublishService(page: Page, ip = "192.0.2.5") {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/nat");
  await page.goto("/wizard/");
  await loaded;
  await page.getByRole("button", { name: /Publish Internal Service/ }).click();
  await page.getByPlaceholder("e.g. 192.168.1.10").fill(ip);
}

test("the publish-service wizard rejects a non-IPv4 server address at the server step", async ({ page }) => {
  await mockWizardAPI(page);
  await openPublishService(page);
  const ip = page.getByPlaceholder("e.g. 192.168.1.10");
  await page.getByPlaceholder("e.g. 443").fill("443");
  const next = page.getByRole("button", { name: "Next", exact: true });

  for (const bad of ["192.0.2", "192.0.2.256", "server.local", "2001:db8::5"]) {
    await ip.fill(bad);
    await expect(page.getByRole("alert").filter({ hasText: `"${bad}" is not a valid IPv4 address` })).toBeVisible();
    await expect(ip).toHaveAttribute("aria-invalid", "true");
    await expect(ip).toHaveAttribute("aria-describedby", "wizard-ip-error");
    await expect(next).toBeDisabled();
  }

  await ip.fill("");
  await expect(page.locator("#wizard-ip-error")).toHaveCount(0);
  await expect(next).toBeDisabled();

  await ip.fill("192.0.2.5");
  await expect(page.locator("#wizard-ip-error")).toHaveCount(0);
  await expect(ip).not.toHaveAttribute("aria-invalid", "true");
  await expect(next).toBeEnabled();
});

test("the publish-service wizard rejects an out-of-range port at the server step", async ({ page }) => {
  await mockWizardAPI(page);
  await openPublishService(page);
  const port = page.getByPlaceholder("e.g. 443");
  const next = page.getByRole("button", { name: "Next", exact: true });

  for (const bad of ["0", "65536", "1.5"]) {
    await port.fill(bad);
    await expect(page.getByRole("alert").filter({ hasText: `"${bad}" is not a valid port (1-65535)` })).toBeVisible();
    await expect(port).toHaveAttribute("aria-invalid", "true");
    await expect(port).toHaveAttribute("aria-describedby", "wizard-port-error");
    await expect(next).toBeDisabled();
  }

  await port.fill("");
  await expect(page.locator("#wizard-port-error")).toHaveCount(0);
  await expect(next).toBeDisabled();

  await port.fill("65535");
  await expect(page.locator("#wizard-port-error")).toHaveCount(0);
  await expect(port).not.toHaveAttribute("aria-invalid", "true");
  await expect(next).toBeEnabled();
});

test("the publish-service wizard stages the address and port accepted at the server step", async ({ page }) => {
  const staged = await mockWizardAPI(page);
  await openPublishService(page, " 192.0.2.5 ");
  await page.getByPlaceholder("e.g. 443").fill("502");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("combobox").selectOption("wan");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("Port forward and firewall rule staged", { exact: false })).toBeVisible();
  expect(staged).toHaveLength(1);
  expect(staged[0]).toMatchObject({ portForwards: [{ listenPort: 502, destPort: 502, destIp: "192.0.2.5", ingressZone: "wan" }] });
});
