import { expect, test } from "@playwright/test";
import type { DHCPConfig } from "../lib/api";

for (const stored of [undefined, false, true]) {
  test(`DHCP authority ${String(stored)} loads, saves and refreshes`, async ({ page }) => {
    let config: DHCPConfig = { enabled: false, ...(stored === undefined ? {} : { authoritative: stored }) };
    const writes: DHCPConfig[] = [];
    await page.route("**/api/v1/**", async (route) => {
      const req = route.request();
      const path = new URL(req.url()).pathname;
      if (path.endsWith("/services/dhcp")) {
        if (req.method() === "POST") {
          config = req.postDataJSON() as DHCPConfig;
          writes.push(config);
          return route.fulfill({ headers: { "X-Containd-Config": "staged" }, json: config });
        }
        return route.fulfill({ json: config });
      }
      const data = path.endsWith("/auth/me") || path.endsWith("/auth/session")
        ? { id: "admin-1", username: "containd", role: "admin" }
        : path.endsWith("/dhcp/leases") ? { leases: [] }
          : path.endsWith("/services/status") ? { dhcp: { enabled: false } }
            : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
      await route.fulfill({ json: data });
    });
    await page.goto("/dhcp/");
    const authority = page.getByRole("checkbox", { name: /^Authoritative/ });
    await expect(authority).toBeEnabled();
    if (stored === true) await expect(authority).toBeChecked();
    else await expect(authority).not.toBeChecked();
    // Saving without editing must preserve the stored/default value.
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => writes.length).toBe(1);
    expect(writes[0].authoritative).toBe(stored ?? false);
    await authority.setChecked(!(stored ?? false));
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => writes.length).toBe(2);
    expect(writes[1].authoritative).toBe(!(stored ?? false));
    await page.reload();
    if (stored === true) await expect(authority).not.toBeChecked();
    else await expect(authority).toBeChecked();
  });
}
