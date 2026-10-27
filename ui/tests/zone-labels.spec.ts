import { expect, test, type Page } from "@playwright/test";

import { zoneLabel, zoneName } from "../lib/zones";

// Zones show as "alias (name)" when they have an alias. Every page that
// names a zone uses the same label.

const zones = [{ name: "wan", alias: "Internet" }, { name: "lan" }];

test("zoneLabel and zoneName show the alias with the name", () => {
  expect(zoneLabel({ name: "wan", alias: "Internet" })).toBe("Internet (wan)");
  expect(zoneLabel({ name: "lan" })).toBe("lan");
  expect(zoneLabel({ name: "dmz", alias: "" })).toBe("dmz");
  expect(zoneName(zones, "wan")).toBe("Internet (wan)");
  expect(zoneName(zones, "lan")).toBe("lan");
  expect(zoneName(zones, "gone")).toBe("gone");
});

async function serve(page: Page) {
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
          : path === "/api/v1/interfaces" ? [{ name: "wan", device: "eth1", zone: "wan" }]
          : path === "/api/v1/interfaces/state" ? [{ name: "eth1", up: true, addrs: [] }]
          : path === "/api/v1/assets" ? [{ id: "plc-1", name: "plc-1", zone: "wan" }]
          : path === "/api/v1/firewall/nat" ? {
            enabled: true,
            portForwards: [{ id: "pf-1", enabled: true, ingressZone: "wan", proto: "tcp", listenPort: 8443, destIp: "192.0.2.5" }],
          } : {};
    await route.fulfill({ json });
  });
}

test("NAT labels zones with their alias", async ({ page }) => {
  await serve(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/nat");
  await page.goto("/nat/");
  await loaded;
  await expect(page.getByRole("cell", { name: "Internet (wan)", exact: true })).toBeVisible();
  await expect(page.getByRole("option", { name: "ingress:Internet (wan)", exact: true })).toHaveCount(1);
  await expect(page.getByRole("option", { name: "Internet (wan)", exact: true })).toHaveCount(1);
});

test("the wizard labels zones with their alias", async ({ page }) => {
  await serve(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/zones");
  await page.goto("/wizard/");
  await loaded;
  await page.getByRole("button", { name: /Allow LAN Internet Access/ }).click();
  await expect(page.getByRole("option", { name: "Internet (wan)", exact: true })).toHaveCount(1);
  await expect(page.getByRole("option", { name: "lan", exact: true })).toHaveCount(1);
});

test("interfaces label zones with their alias", async ({ page }) => {
  await serve(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/interfaces");
  await page.goto("/interfaces/");
  await loaded;
  await expect(page.getByRole("cell", { name: "Internet (wan)", exact: true })).toBeVisible();
  await expect(page.getByRole("option", { name: "Internet (wan)", exact: true })).toHaveCount(1);
});

test("assets label zones with their alias", async ({ page }) => {
  await serve(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/assets");
  await page.goto("/assets/");
  await loaded;
  await expect(page.getByRole("cell", { name: "Internet (wan)", exact: true })).toBeVisible();
  await expect(page.getByRole("option", { name: "Internet (wan)", exact: true })).toHaveCount(1);
});

test("packet capture labels zones with their alias", async ({ page }) => {
  await serve(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/zones");
  await page.goto("/dataplane/");
  await loaded;
  await expect(page.getByRole("checkbox", { name: "Internet (wan)", exact: true })).toHaveCount(1);
  await expect(page.getByRole("checkbox", { name: "lan", exact: true })).toHaveCount(1);
});
