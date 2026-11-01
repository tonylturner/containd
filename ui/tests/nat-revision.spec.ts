import { expect, test } from "@playwright/test";
import type { NATConfig } from "../lib/api";

const token = (n: number) => `0123456789abcdef.${n}`;

test("late NAT acknowledgement cannot give old data a newer refresh revision", async ({ page }) => {
  let counter = 1;
  let nat: NATConfig = { enabled: false, egressZone: "wan", sourceZones: ["lan"], portForwards: [] };
  let holdReads = false;
  let releaseSave!: () => void;
  let releaseReads!: () => void;
  const saved = new Promise<void>(r => { releaseSave = r; });
  const reads = new Promise<void>(r => { releaseReads = r; });
  const writes: { body: NATConfig; revision?: string }[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() === "POST" && path === "/firewall/nat") {
      const body = request.postDataJSON();
      const revision = request.headers()["x-containd-if-revision"];
      writes.push({ body, revision });
      if (revision !== token(counter)) return route.fulfill({ status: 412, json: {
        error: "changed", code: "config_revision_mismatch", currentRevision: token(counter),
      } });
      nat = body;
      const resultRevision = token(++counter);
      if (writes.length === 1) await saved;
      return route.fulfill({ json: body, headers: { "X-Containd-Revision": resultRevision, "X-Containd-Config": "staged" } });
    }
    if (holdReads && !path.startsWith("/auth/")) await reads;
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/firewall/nat" ? nat
      : path === "/zones" ? [{ name: "wan" }, { name: "lan" }]
      : path === "/firewall/rules" ? []
      : path === "/config/diff" ? { changed: false, changedSections: [], running: {}, candidate: {} }
      : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": token(counter) } });
  });
  try {
    await page.goto("/nat/");
    await page.getByRole("button", { name: "Off", exact: true }).click();
    await page.getByRole("button", { name: "Save NAT", exact: true }).click();
    await expect.poll(() => counter).toBe(2);
    const remoteForward = { id: "remote", enabled: true, ingressZone: "wan", proto: "tcp" as const, listenPort: 8443, destIp: "192.0.2.22", destPort: 443 };
    nat = { ...nat, portForwards: [remoteForward] };
    counter++;
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByRole("cell", { name: "192.0.2.22:443", exact: true })).toBeVisible();
    holdReads = true;
    releaseSave();
    await expect(page.getByRole("button", { name: "Save NAT", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "On", exact: true }).click();
    await page.getByRole("button", { name: "Save NAT", exact: true }).click();
    await expect.poll(() => writes.length).toBe(2);
    // A stale payload must either be rejected with its old revision or keep B's edit.
    expect(writes[1].revision !== token(3) || writes[1].body.portForwards?.some((pf) => pf.id === "remote")).toBe(true);
  } finally {
    releaseSave();
    releaseReads();
  }
});
