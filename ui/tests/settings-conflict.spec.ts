import { expect, test } from "@playwright/test";
import { observation, protectionAPI } from "./fixtures/protection-api";

test("management conflict reload preserves another operator's firewall rule", async ({ page }) => {
  await protectionAPI(page, observation());
  let revision = "0123456789abcdef.1";
  let candidate = {
    system: { hostname: "appliance" },
    firewall: { defaultAction: "DENY", rules: [] as { id: string; action: string }[] },
  };
  const writes: { body: typeof candidate; revision?: string }[] = [];
  await page.route("**/api/v1/config/candidate", async route => {
    const request = route.request();
    if (request.method() === "GET") {
      return route.fulfill({ json: candidate, headers: { "X-Containd-Revision": revision } });
    }
    writes.push({ body: request.postDataJSON(), revision: request.headers()["x-containd-if-revision"] });
    if (writes.at(-1)?.revision !== revision) {
      return route.fulfill({
        status: 412,
        json: { error: "revision conflict", code: "config_revision_mismatch", currentRevision: revision },
      });
    }
    candidate = request.postDataJSON();
    revision = "0123456789abcdef.3";
    return route.fulfill({ json: { status: "staged" }, headers: { "X-Containd-Revision": revision } });
  });
  await page.route("**/api/v1/config/validate", route => route.fulfill({ json: { status: "valid" } }));
  await page.goto("/system/settings/");
  const hostname = page.getByLabel("Hostname", { exact: true });
  const save = page.getByRole("button", { name: "Save management access", exact: true });
  await expect(hostname).toHaveValue("appliance");
  await hostname.fill("management-edit");

  // A different operator stages a firewall rule after this form's read.
  const otherRule = { id: "other-operator-rule", action: "ALLOW" };
  candidate = { ...candidate, firewall: { ...candidate.firewall, rules: [otherRule] } };
  revision = "0123456789abcdef.2";
  await save.click();
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  expect(writes).toHaveLength(1);
  expect(writes[0].revision).toBe("0123456789abcdef.1");
  expect(writes[0].body.firewall.rules).toEqual([]);
  await expect(hostname).toHaveValue("management-edit");
  await expect(page.getByRole("button", { name: "Keep my edits", exact: true })).toHaveCount(0);
  await expect(save).toBeDisabled();
  await page.getByRole("button", { name: "Reload", exact: true }).click();
  await expect(hostname).toHaveValue("appliance");
  await expect(save).toBeEnabled();
  await hostname.fill("management-edit");
  await save.click();
  await expect(page.getByRole("status").filter({ hasText: "Management access staged" })).toBeVisible();
  expect(writes).toHaveLength(2);
  expect(writes[1].revision).toBe("0123456789abcdef.2");
  expect(writes[1].body).toEqual({ ...candidate, system: { hostname: "management-edit" } });
  expect(writes[1].body.firewall.rules).toEqual([otherRule]);
  expect(candidate.firewall.rules).toEqual([otherRule]);
});
