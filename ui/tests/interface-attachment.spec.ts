import { expect, test } from "@playwright/test";
import { interfaceAttachment } from "../lib/interface-addresses";
import { CONFIG_COMMITTED } from "../lib/config-events";
import { observation, protectionAPI } from "./fixtures/protection-api";

const state = (name: string, up = true) => ({
  name, up, index: 1, mtu: 1500, mac: "", addrs: [],
});

test("attachment distinguishes matching up, down, absent and unknown state", () => {
  const iface = { name: "lan1" };
  expect(interfaceAttachment(iface, [state("lan1")])).toBe("attached");
  expect(interfaceAttachment(iface, [state("lan1", false)])).toBe("down");
  expect(interfaceAttachment(iface, [state("eth0")])).toBe("not attached");
  expect(interfaceAttachment(iface, [])).toBe("not attached");
  expect(interfaceAttachment(iface, null)).toBe("unknown");
});

test("interface rows show live attachment without assignment controls or writes", async ({ page }) => {
  await protectionAPI(page, observation());
  const writes: string[] = [];
  page.on("request", request => {
    if (request.url().includes("/api/v1/") && request.method() !== "GET") writes.push(request.url());
  });
  let unavailable = false;
  let states = [state("lan1"), state("wan", false), state("eth0")];
  await page.route("**/api/v1/interfaces", route => route.fulfill({
    json: [{ name: "lan1" }, { name: "wan" }, { name: "dmz" }],
    headers: { "X-Containd-Revision": "0123456789abcdef.1" },
  }));
  await page.route("**/api/v1/interfaces/state", route => route.fulfill(unavailable
    ? { status: 503, json: { error: "discovery unavailable" } }
    : { json: states }));
  await Promise.all([page.waitForResponse("**/api/v1/interfaces/state"), page.goto("/interfaces/")]);
  const row = (name: string) => page.getByRole("row").filter({
    has: page.getByRole("cell", { name, exact: true }),
  });
  const attachment = (name: string) => row(name).locator('[data-label="Attachment"]');
  await expect(attachment("lan1")).toHaveText("attached");
  await expect(attachment("wan")).toHaveText("down");
  await expect(attachment("dmz")).toHaveText("not attached");
  await expect(page.getByRole("button", { name: "Auto-assign", exact: true })).toHaveCount(0);
  await expect(page.getByText(/Compose names each NIC with/)).toBeVisible();
  await expect(page.getByRole("link", { name: "Interfaces documentation" })).toHaveAttribute("href", "/docs/policy-model/");
  await row("lan1").getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByPlaceholder("Network device (e.g. eth0)")).toHaveCount(0);
  const alias = row("lan1").getByPlaceholder("alias (optional)");
  await alias.fill("Retained alias");

  // A normal config refresh also updates attachment without acknowledging edits.
  unavailable = true;
  await page.evaluate(event => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED);
  for (const name of ["lan1", "wan", "dmz"]) await expect(attachment(name)).toHaveText("unknown");
  await expect(alias).toHaveValue("Retained alias");
  unavailable = false;
  states = [state("dmz")];
  await page.getByRole("status").filter({ hasText: "Live device information is unavailable" }).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(attachment("dmz")).toHaveText("attached");
  await expect(attachment("lan1")).toHaveText("not attached");
  await expect(alias).toHaveValue("Retained alias");
  expect(writes).toEqual([]);
});
