import { expect, test } from "@playwright/test";

const revision = "0123456789abcdef.1";
const iface = {
  name: "lan1", alias: "Inside", type: "physical", device: "eth2", zone: "lan",
  addressMode: "static", addresses: ["192.0.2.2/24", "2001:db8::2/64"],
  access: { mgmt: true, ssh: true, http: true, https: true },
};

test("interface inspect is keyboard operable and edit preserves the exact payload", async ({ page }) => {
  let payload: unknown;
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/interfaces/lan1" && route.request().method() === "PATCH") {
      payload = route.request().postDataJSON();
      await route.fulfill({ json: { ...iface, alias: "Inside updated" }, headers: { "X-Containd-Revision": revision } });
      return;
    }
    const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] }
      : path === "/api/v1/interfaces" ? [iface]
      : path === "/api/v1/interfaces/state" ? [{ name: "eth2", up: true, mtu: 1500, mac: "02:00:00:00:00:02", addrs: ["198.51.100.2/24"] }]
      : path === "/api/v1/zones" ? [{ name: "lan", alias: "Plant" }]
      : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
  await page.goto("/interfaces/");
  const inspect = page.getByRole("button", { name: "Inspect", exact: true });
  await expect(inspect).toHaveAttribute("aria-expanded", "false");
  await inspect.focus();
  await page.keyboard.press("Enter");
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("MTU: 1500")).toBeVisible();
  await expect(page.getByText("Detected address: 198.51.100.2/24")).toBeVisible();
  await page.keyboard.press("Space");
  await expect(inspect).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByText("MTU: 1500")).toBeHidden();
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "lan1", exact: true }) });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await row.getByPlaceholder("alias (optional)").fill("Inside updated");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => payload).toEqual({
    alias: "Inside updated", type: iface.type, device: iface.device, zone: iface.zone,
    addressMode: iface.addressMode, addresses: iface.addresses, access: iface.access, members: [], parent: "", vlanId: 0, gateway: "",
  });
  await expect(inspect).toBeFocused();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("saved bridge and access settings open inspection without hiding management warnings", async ({ page }) => {
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] }
      : path === "/api/v1/interfaces" ? [{ ...iface, type: "bridge", members: ["eth3", "eth4"], access: { mgmt: false } }]
      : path === "/api/v1/interfaces/state" || path === "/api/v1/zones" ? []
      : path === "/api/v1/system/management-reservation" ? { active: false, bootFault: "invalid bridge member", recovery: "recovery pending" }
      : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
  await page.goto("/interfaces/");
  await expect(page.getByRole("button", { name: "Inspect", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("invalid bridge member", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Inspect", exact: true }).click();
  await expect(page.getByText("Access customized", { exact: false })).toBeVisible();
  await expect(page.getByText("invalid bridge member", { exact: true })).toBeVisible();
});

test("view-only operators can inspect network details without edit actions", async ({ page }) => {
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.includes("/auth/") ? { id: "reader", username: "reader", role: "viewer" }
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] }
      : path === "/api/v1/interfaces" ? [iface]
      : path === "/api/v1/interfaces/state" ? [{ name: "eth2", up: true, mtu: 1500, addrs: [] }]
      : path === "/api/v1/zones" ? [{ name: "lan" }]
      : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
  await page.goto("/interfaces/");
  const inspect = page.getByRole("button", { name: "Inspect", exact: true });
  await inspect.click();
  await expect(page.getByText("MTU: 1500")).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete", exact: true })).toHaveCount(0);
});
