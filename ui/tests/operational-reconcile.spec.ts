import { expect, test } from "@playwright/test";
import type { Interface, RoutingConfig } from "../lib/api";

const revision = (counter: number) => `0123456789abcdef.${counter}`;

// Also exercise older servers that still return a read revision on Reconcile.
for (const legacyHeader of [false, true]) {
  for (const surface of ["routing", "interface row", "interface creation"] as const) {
    test(`${surface} draft retains R1 across Reconcile at R2 (revision header: ${legacyHeader})`, async ({ page }) => {
      let counter = 1;
      let routing: RoutingConfig = { gateways: [], routes: [], rules: [] };
      let interfaces: Interface[] = [{ name: "wan", alias: "original", type: "physical" }];
      const writes: { base?: string; body: unknown }[] = [];
      const reconciles: { base?: string; body: unknown }[] = [];
      const domain = surface === "routing" ? "routing" : "interfaces";
      await page.addInitScript(() => {
        localStorage.setItem("containd.auth.token", "test");
        localStorage.setItem("containd.auth.role", "admin");
      });
      await page.route("**/api/v1/**", async route => {
        const request = route.request();
        const path = new URL(request.url()).pathname.replace("/api/v1", "");
        if (request.method() !== "GET") {
          const body: unknown = request.postDataJSON();
          const base = request.headers()["x-containd-if-revision"];
          if (path === `/${domain}/reconcile`) {
            reconciles.push({ base, body });
            return route.fulfill({
              json: { status: "reconciled" },
              headers: legacyHeader ? { "X-Containd-Revision": revision(counter) } : {},
            });
          }
          writes.push({ base, body });
          if (base !== revision(counter)) return route.fulfill({
            status: 412,
            json: { error: "changed", code: "config_revision_mismatch", currentRevision: revision(counter) },
          });
          if (domain === "routing") routing = body as RoutingConfig;
          else if (path === "/interfaces/wan") interfaces = [{ ...interfaces[0], ...body as Partial<Interface> }];
          else interfaces.push(body as Interface);
          counter++;
          return route.fulfill({
            json: domain === "routing" ? routing : interfaces[interfaces.length - 1],
            headers: { "X-Containd-Revision": revision(counter), "X-Containd-Config": "staged" },
          });
        }
        const data: Record<string, unknown> = {
          "/auth/me": { id: "admin", role: "admin" }, "/auth/session": { id: "admin", role: "admin" },
          "/routing": routing, "/routing/os": {}, "/interfaces": interfaces,
          "/interfaces/state": [], "/zones": [],
          "/config/diff": { changed: false, changedSections: [], pendingConfirm: null, running: {}, candidate: {} },
        };
        return route.fulfill({ json: data[path] ?? {}, headers: { "X-Containd-Revision": revision(counter) } });
      });
      await page.goto(`/${domain}/`);
      const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "wan", exact: true }) });
      if (surface === "routing") {
        await page.getByText("Add static route (advanced)", { exact: true }).click();
      }
      if (surface === "interface row") {
        await row.getByRole("button", { name: "Edit", exact: true }).click();
      }
      const input = surface === "routing" ? page.getByPlaceholder("dst (CIDR or default)")
        : surface === "interface row" ? row.getByPlaceholder("alias (optional)")
        : page.getByPlaceholder("name (e.g. tunnel1)");
      const value = surface === "routing" ? "198.51.100.0/24" : "unfinished";
      await expect(input).toBeEnabled();
      await input.fill(value);

      // A separate operator saves R2 without refreshing this tab's R1 draft.
      const otherBody = domain === "routing"
        ? { gateways: [], routes: [{ dst: "203.0.113.0/24", iface: "wan" }], rules: [] }
        : { alias: "other operator" };
      const status = await page.evaluate(async ({ domain, body, base }) => {
        const response = await fetch(`/api/v1/${domain === "routing" ? "routing" : "interfaces/wan"}`, {
          method: domain === "routing" ? "POST" : "PATCH",
          headers: { "Content-Type": "application/json", Authorization: "Bearer test", "X-Containd-If-Revision": base },
          body: JSON.stringify(body),
        });
        await response.json();
        return response.status;
      }, { domain, body: otherBody, base: revision(1) });
      expect(status).toBe(200);
      expect(counter).toBe(2);

      await page.getByRole("button", { name: "Reconcile live", exact: true }).click();
      await page.getByRole("dialog").getByRole("button", { name: "Reconcile", exact: true }).click();
      await expect(page.getByText(domain === "routing" ? "Routing reconciled." : "Interfaces reconciled.", { exact: true })).toBeVisible();
      await expect(input).toHaveValue(value);
      const save = surface === "routing" ? page.getByRole("button", { name: "Add route", exact: true })
        : surface === "interface row" ? row.getByRole("button", { name: "Save", exact: true })
        : page.getByRole("button", { name: "Create", exact: true });
      await save.click();
      await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
      expect(writes).toHaveLength(2);
      expect(writes[1].base).toBe(revision(1));
      expect(reconciles).toEqual([{ body: { confirm: "REPLACE" }, base: undefined }]);
      expect(counter).toBe(2);
      if (domain === "routing") expect(routing).toEqual(otherBody);
      else expect(interfaces).toEqual([{ name: "wan", alias: "other operator", type: "physical" }]);
      // Review consent itself never retries a save.
      await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
      expect(writes).toHaveLength(2);
      expect(counter).toBe(2);
    });
  }
}
