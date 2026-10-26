import { expect, test, type Page } from "@playwright/test";

// The diagnostics page checks IPv4 addresses with the shared rule: octets
// without leading zeros, as the server's parser requires.

async function openDiagnostics(page: Page) {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] }
        : path === "/api/v1/interfaces" ? [{ name: "lan", device: "eth0", zone: "lan" }]
          : path === "/api/v1/interfaces/state"
            ? [{ name: "eth0", up: true, addrs: ["fe80::1/64", "192.0.2.010/24", "192.0.2.10/24"] }]
            : {};
    await route.fulfill({ json });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/interfaces/state");
  await page.goto("/diagnostics/");
  await loaded;
  return errors;
}

test("diagnostics offers the first valid IPv4 interface address", async ({ page }) => {
  const errors = await openDiagnostics(page);
  const connectivity = page.getByRole("region", { name: "Interface Connectivity", exact: true });
  await expect(connectivity.getByTitle("Use lan OS/Docker IP: 192.0.2.10")).toBeVisible();
  expect(errors).toEqual([]);
});

test("temporary blocks refuse IPv4 addresses with leading zeros", async ({ page }) => {
  const errors = await openDiagnostics(page);
  const hostError = page.getByText("Enter a valid IPv4 address for host block.", { exact: true });
  const hostIP = page.getByPlaceholder("source or destination IP");
  const blockHost = page.getByRole("button", { name: "Block host", exact: true });
  for (const bad of ["192.0.2.07", "256.0.0.1", "192.0.2"]) {
    await hostIP.fill(bad);
    await blockHost.click();
    await expect(hostError).toBeVisible();
  }
  await hostIP.fill(" 192.0.2.7 ");
  await blockHost.click();
  await expect(page.getByText("Block all traffic matching IP 192.0.2.7?", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();

  const flowError = page.getByText("Enter valid IPv4 addresses for flow block.", { exact: true });
  await page.getByPlaceholder("source IP", { exact: true }).fill("010.0.0.1");
  await page.getByPlaceholder("destination IP", { exact: true }).fill("192.0.2.8");
  const blockFlow = page.getByRole("button", { name: "Block flow", exact: true });
  await blockFlow.click();
  await expect(flowError).toBeVisible();

  await page.getByPlaceholder("source IP", { exact: true }).fill("10.0.0.1");
  await page.getByPlaceholder("dst port").fill("0");
  await blockFlow.click();
  await expect(page.getByText("Enter a valid destination port (1-65535).", { exact: true })).toBeVisible();

  await page.getByPlaceholder("dst port").fill("502");
  await blockFlow.click();
  await expect(page.getByText("Block flow 10.0.0.1 -> 192.0.2.8:502 (tcp)?", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});
