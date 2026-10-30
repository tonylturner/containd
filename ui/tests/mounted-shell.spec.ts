import { expect, test, type Page } from "@playwright/test";

async function mockAPI(page: Page) {
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname.replace(/^\/containd(?=\/)/, "");
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false }
      : path.endsWith("/services/dns") ? { enabled: true, listenPort: 53 } : {};
    return route.fulfill({ json });
  });
}

for (const mount of ["", "/containd"]) {
  test(`dashboard chrome uses the route rather than the ${mount || "root"} mount`, async ({ page }) => {
    await mockAPI(page);
    const loaded = page.waitForResponse("**/api/v1/dashboard");
    await page.goto("/");
    await loaded;
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
    // Next's history integration updates usePathname without needing a proxy
    // for this focused component regression test.
    await page.evaluate((path) => window.history.replaceState(null, "", path), `${mount}/`);
    const navigation = page.getByRole("navigation", { name: "Main navigation" });
    const dashboard = navigation.getByRole("link", { name: "Dashboard", exact: true });
    await expect(dashboard).toHaveAttribute("aria-current", "page");
    await expect(dashboard).toHaveAttribute("href", `${mount}/`);
    await expect(page.getByRole("navigation", { name: "Breadcrumb", exact: true })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Help & documentation" })).toHaveAttribute("href", `${mount}/docs/`);

    await page.evaluate((path) => window.history.replaceState(null, "", path), `${mount}/system/services/dns/`);
    await expect(navigation.getByRole("button", { name: "Services", exact: true })).toHaveAttribute("aria-expanded", "true");
    await expect(navigation.getByRole("link", { name: "DNS", exact: true })).toHaveAttribute("aria-current", "page");
  });

  test(`nested breadcrumbs and navigation stay inside the ${mount || "root"} mount`, async ({ page }) => {
    await mockAPI(page);
    const loaded = page.waitForResponse("**/api/v1/services/dns");
    await page.goto("/system/services/dns/");
    await loaded;
    await expect(page.getByRole("heading", { name: "DNS", exact: true })).toBeVisible();
    await page.evaluate((path) => window.history.replaceState(null, "", path), `${mount}/system/services/dns/`);
    const breadcrumb = page.getByRole("navigation", { name: "Breadcrumb", exact: true });
    await expect(breadcrumb.locator("li")).toHaveText(["Home", "System", "Services", "Dns"]);
    for (const [label, path] of [["Home", "/"], ["System", "/system/"], ["Services", "/system/services/"]]) {
      await expect(breadcrumb.getByRole("link", { name: label, exact: true })).toHaveAttribute("href", `${mount}${path}`);
    }
    await expect(page.getByRole("link", { name: "Help & documentation" })).toHaveAttribute("href", `${mount}/docs/services/`);
    const navigation = page.getByRole("navigation", { name: "Main navigation" });
    await navigation.getByRole("button", { name: "Services", exact: true }).click();
    const dns = navigation.getByRole("link", { name: "DNS", exact: true });
    await expect(dns).toHaveAttribute("aria-current", "page");
    await expect(dns).toHaveAttribute("href", `${mount}/system/services/dns/`);
  });
}
