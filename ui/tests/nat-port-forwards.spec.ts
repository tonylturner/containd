import { expect, test, type Page } from "@playwright/test";

// Adding a port forward checks its ports with the shared port rule. The card
// has one error banner for the whole row, so each message names its field.

const zones = [{ name: "wan" }, { name: "lan" }];

async function openNAT(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] }
        : path === "/api/v1/zones" ? zones
          : path === "/api/v1/firewall/nat" ? { enabled: true, portForwards: [] } : {};
    await route.fulfill({ json });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/nat");
  await page.goto("/nat/");
  await loaded;
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();
}

test("adding a port forward rejects ports outside 1-65535 and fractional ports", async ({ page }) => {
  await openNAT(page);
  const listen = page.getByPlaceholder("listen port");
  const destIp = page.getByPlaceholder("dest ip");
  const destPort = page.getByPlaceholder("dest port (opt)");
  const add = page.getByRole("button", { name: "Add", exact: true });
  await destIp.fill("192.0.2.5");

  await add.click();
  await expect(page.getByText("Listen port is required.", { exact: true })).toBeVisible();

  for (const bad of ["0", "65536", "1.5"]) {
    await listen.fill(bad);
    await add.click();
    await expect(page.getByText(`Listen port: "${bad}" is not a valid port (1-65535).`, { exact: true })).toBeVisible();
  }

  await listen.fill("8443");
  for (const bad of ["0", "70000", "443.5"]) {
    await destPort.fill(bad);
    await add.click();
    await expect(page.getByText(`Destination port: "${bad}" is not a valid port (1-65535).`, { exact: true })).toBeVisible();
  }
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();

  await destPort.fill("443");
  await add.click();
  await expect(page.getByRole("cell", { name: "192.0.2.5:443", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "8443", exact: true })).toBeVisible();
  await expect(page.getByText("is not a valid port", { exact: false })).toHaveCount(0);
});
