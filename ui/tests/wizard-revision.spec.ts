import { expect, test, type Page } from "@playwright/test";
import type { NATConfig } from "../lib/api";

const token = (n: number) => `0123456789abcdef.${n}`;

async function stageLAN(page: Page) {
  await page.getByRole("button", { name: /Allow LAN Internet Access/ }).click();
  await page.getByRole("combobox").selectOption("lan");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("combobox").selectOption("wan");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Stage", exact: true }).click();
}

test("Refresh overtakes a held wizard acknowledgement without authorizing an old NAT payload", async ({ page }) => {
  let counter = 1;
  let nat: NATConfig = { enabled: false, portForwards: [] };
  let holdReads = false;
  let releaseSave!: () => void;
  let releaseReads!: () => void;
  const save = new Promise<void>(resolve => { releaseSave = resolve; });
  const reads = new Promise<void>(resolve => { releaseReads = resolve; });
  const writes: { body: NATConfig; revision?: string }[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (req.method() === "POST") {
      const body = req.postDataJSON();
      const revision = req.headers()["x-containd-if-revision"];
      if (revision !== token(counter)) return route.fulfill({ status: 412, json: {
        error: "changed", code: "config_revision_mismatch", currentRevision: token(counter),
      } });
      const resultRevision = token(++counter);
      if (path === "/firewall/nat") {
        writes.push({ body, revision });
        nat = body;
        if (writes.length === 1) await save;
      }
      return route.fulfill({ json: body, headers: { "X-Containd-Revision": resultRevision, "X-Containd-Config": "staged" } });
    }
    if (holdReads && !path.startsWith("/auth/")) await reads;
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/zones" ? [{ name: "lan", alias: counter >= 4 ? "Fresh LAN" : "" }, { name: "wan" }]
      : path === "/firewall/nat" ? nat
      : path === "/config/diff" ? { changed: false, changedSections: [], pendingConfirm: null, running: {}, candidate: {} }
      : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(counter) } });
  });
  try {
    await page.goto("/wizard/");
    await stageLAN(page);
    await expect.poll(() => writes.length).toBe(1);
    nat = { ...nat, portForwards: [{ id: "remote", enabled: true, ingressZone: "wan",
      proto: "tcp", listenPort: 8443, destIp: "192.0.2.22", destPort: 443 }] };
    counter++;
    const refreshed = page.waitForResponse("**/api/v1/firewall/nat");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await (await refreshed).finished();
    await expect(page.getByRole("button", { name: /Allow LAN Internet Access/ })).toBeVisible();
    await page.getByRole("button", { name: /Allow LAN Internet Access/ }).click();
    await expect(page.getByRole("combobox").locator('option[value="lan"]')).toContainText("Fresh LAN");
    holdReads = true;
    releaseSave();
    await expect(page.getByRole("heading", { name: "Success", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Run another wizard", exact: true }).click();
    await stageLAN(page);
    await expect.poll(() => writes.length).toBe(2);
    expect(writes[1].revision).toBe(token(5));
    expect(writes[1].body.portForwards?.map(forward => forward.id)).toContain("remote");
  } finally {
    releaseSave();
    releaseReads();
  }
});
