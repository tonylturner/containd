import { expect, test, type Page } from "@playwright/test";

// Adding a port forward checks its ports and IPv4 destination with the shared
// rules. The card has one error banner for the whole row, so each message
// names its field. The ingress zone defaults to "wan" only when that zone
// exists; otherwise Add asks for a choice.

type Zone = { name: string; alias?: string };

async function openNAT(page: Page, zones: Zone[] = [{ name: "wan" }, { name: "lan" }]) {
  const staged: unknown[] = [];
  const forwards: Record<string, unknown>[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/firewall/port-forwards" && route.request().method() === "POST") {
      const body = route.request().postDataJSON();
      staged.push(body);
      forwards.push(body.forward);
      await route.fulfill({ json: { forward: body.forward, ...(body.allowRule ? { placement: { rule: { id: "allow-published" }, index: 0 } } : {}) } });
      return;
    }
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] }
        : path === "/api/v1/zones" ? zones
          : path === "/api/v1/firewall/nat" ? { enabled: true, portForwards: forwards }
            : path === "/api/v1/firewall/rules" ? [] : {};
    await route.fulfill({ json });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/nat");
  await page.goto("/nat/");
  await loaded;
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();
  return staged;
}

test("adding a port forward rejects ports outside 1-65535 and ports not in decimal digits", async ({ page }) => {
  await openNAT(page);
  const listen = page.getByPlaceholder("listen port");
  const destIp = page.getByPlaceholder("dest ip");
  const destPort = page.getByPlaceholder("dest port (opt)");
  const add = page.getByRole("button", { name: "Add", exact: true });
  await destIp.fill("192.0.2.5");

  await add.click();
  await expect(page.getByText("Listen port is required.", { exact: true })).toBeVisible();

  for (const bad of ["0", "65536", "1.5", "1e3", "0x50"]) {
    await listen.fill(bad);
    await add.click();
    await expect(page.getByText(`Listen port: "${bad}" is not a valid port (1-65535).`, { exact: true })).toBeVisible();
  }

  await listen.fill("8443");
  for (const bad of ["0", "70000", "443.5", "1e3", "0x50"]) {
    await destPort.fill(bad);
    await add.click();
    await expect(page.getByText(`Destination port: "${bad}" is not a valid port (1-65535).`, { exact: true })).toBeVisible();
  }
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();

  await destPort.fill("443");
  await add.click();
  await expect(page.getByRole("cell", { name: "192.0.2.5:443", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "8443", exact: true })).toBeVisible();
  await expect(page.getByText("is not a valid port", { exact: false })).toHaveCount(0);
});

test("adding a port forward rejects a destination that is not IPv4", async ({ page }) => {
  await openNAT(page);
  const destIp = page.getByPlaceholder("dest ip");
  const add = page.getByRole("button", { name: "Add", exact: true });
  await page.getByPlaceholder("listen port").fill("8443");

  await add.click();
  await expect(page.getByText("Destination IP is required.", { exact: true })).toBeVisible();

  for (const bad of ["192.0.2", "192.0.2.05", "server.local", "2001:db8::5"]) {
    await destIp.fill(bad);
    await add.click();
    await expect(page.getByText(`Destination IP: "${bad}" is not a valid IPv4 address.`, { exact: true })).toBeVisible();
  }
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();

  await destIp.fill(" 192.0.2.5 ");
  await add.click();
  await expect(page.getByRole("cell", { name: "192.0.2.5:8443", exact: true })).toBeVisible();
});

test("the ingress zone defaults to wan when that zone exists", async ({ page }) => {
  await openNAT(page);
  await expect(page.getByLabel("Ingress zone")).toHaveValue("wan");
  await page.getByPlaceholder("listen port").fill("8443");
  await page.getByPlaceholder("dest ip").fill("192.0.2.5");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByRole("cell", { name: "wan", exact: true })).toBeVisible();
});

test("without a wan zone, adding a port forward needs an ingress zone choice", async ({ page }) => {
  const staged = await openNAT(page, [{ name: "lan" }, { name: "dmz", alias: "Perimeter" }]);
  const ingress = page.getByLabel("Ingress zone");
  await expect(ingress).toHaveValue("");
  await expect(page.getByRole("option", { name: "ingress: choose a zone", exact: true })).toHaveCount(1);
  await page.getByPlaceholder("listen port").fill("8443");
  await page.getByPlaceholder("dest ip").fill("192.0.2.5");
  const add = page.getByRole("button", { name: "Add", exact: true });
  await add.click();
  await expect(page.getByText("Ingress zone is required.", { exact: true })).toBeVisible();
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();

  await ingress.selectOption("dmz");
  await expect(page.getByRole("option", { name: "ingress: choose a zone", exact: true })).toHaveCount(0);
  await add.click();
  await expect(page.getByText("Ingress zone is required.", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: "Perimeter (dmz)", exact: true })).toBeVisible();
  await expect(page.getByText("matching allow rule allow-published inserted at position 1", { exact: false })).toBeVisible();
  expect(staged).toHaveLength(1);
  expect(staged[0]).toMatchObject({ allowRule: true, forward: { ingressZone: "dmz", listenPort: 8443, destIp: "192.0.2.5" } });
});

test("publish without an allow rule sends false and leaves policy untouched", async ({ page }) => {
  const staged = await openNAT(page);
  await page.getByPlaceholder("listen port").fill("8443");
  await page.getByPlaceholder("dest ip").fill("192.0.2.5");
  await expect(page.getByLabel("Create matching allow rule")).toBeChecked();
  await page.getByLabel("Create matching allow rule").uncheck();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Port forward staged without a matching allow rule", { exact: false })).toBeVisible();
  expect(staged).toHaveLength(1);
  expect(staged[0]).toMatchObject({ allowRule: false });
});

test("publish displays the fail-closed warning and its traffic, not a generated grant", async ({ page }) => {
  await openNAT(page);
  await page.route("**/api/v1/firewall/port-forwards", (route) => route.fulfill({ json: {
    forward: route.request().postDataJSON().forward,
    placement: { forwardId: "pf-test", overlap: "partial", reason: "partial", index: 0, warning: {
      forwardId: "pf-test", ruleIds: ["ics-control"], message: "Partial overlap: no generated grant. Existing policy decides delivery.",
      traffic: { sources: ["198.51.100.0/24"], ingressZone: "wan", backendZones: "any routed egress (unknown)", protocol: "tcp", backend: "192.0.2.5:502", listenAddress: "ingress-local", listenPort: 1502 },
    } },
  } }));
  await page.getByPlaceholder("listen port").fill("1502");
  await page.getByPlaceholder("dest ip").fill("192.0.2.5");
  await page.getByPlaceholder("dest port (opt)").fill("502");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText(/Partial overlap: no generated grant/)).toBeVisible();
  await expect(page.getByText(/Traffic: sources 198.51.100.0\/24, ingress wan, backend zones any routed egress \(unknown\), tcp ingress-local:1502 → 192.0.2.5:502/)).toBeVisible();
  await expect(page.getByText(/inserted at position/)).toHaveCount(0);
});

test("a rejected publish keeps the draft for correction", async ({ page }) => {
  await openNAT(page);
  await page.route("**/api/v1/firewall/port-forwards", (route) => route.fulfill({ status: 400, json: { error: "Overlapping forward" } }));
  await page.getByPlaceholder("listen port").fill("8443");
  await page.getByPlaceholder("dest ip").fill("192.0.2.5");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Overlapping forward", { exact: true })).toBeVisible();
  await expect(page.getByPlaceholder("listen port")).toHaveValue("8443");
  await expect(page.getByRole("button", { name: "Add", exact: true })).toBeEnabled();
});

test("delete confirmation lists rules to edit and delete, links them, and shows the server result", async ({ page }) => {
  await openNAT(page);
  let forwards = [{ id: "pf-test", enabled: true, ingressZone: "wan", proto: "tcp", listenPort: 8443, destIp: "192.0.2.5", destPort: 443 }];
  let rules = [
    { id: "allow-only-this", action: "ALLOW", viaForwards: ["pf-test"] },
    { id: "deny-both", action: "DENY", viaForwards: ["pf-test", "pf-other"] },
    { id: "reset-only-this", action: "RESET", viaForwards: ["pf-test"] },
  ];
  const deleted: string[] = [];
  await page.route("**/api/v1/firewall/nat", (route) => route.fulfill({ json: { enabled: true, portForwards: forwards } }));
  await page.route("**/api/v1/firewall/rules", (route) => route.fulfill({ json: rules }));
  await page.route("**/api/v1/firewall/port-forwards/pf-test", async (route) => {
    expect(route.request().method()).toBe("DELETE");
    deleted.push("pf-test");
    forwards = [];
    rules = [{ id: "deny-both", action: "DENY", viaForwards: ["pf-other"] }];
    await route.fulfill({ json: { deletedRuleIds: ["allow-only-this", "reset-only-this"], editedRuleIds: ["deny-both"] } });
  });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("link", { name: "deny-both", exact: true })).toHaveAttribute("href", "/firewall/#rule-deny-both");
  const remove = page.getByRole("button", { name: "Delete", exact: true });
  await remove.click();
  const dialog = page.getByRole("dialog", { name: "Delete port forward?" });
  await expect(dialog).toContainText("Rules to delete: allow-only-this, reset-only-this.");
  await expect(dialog).toContainText("Rules to edit (remove this forward): deny-both.");
  expect(deleted).toEqual([]);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(deleted).toEqual([]);
  await remove.click();
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByText("Port forward deleted — commit to apply. Deleted rules: allow-only-this, reset-only-this. Edited rules: deny-both.", { exact: true })).toBeVisible();
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();
  expect(deleted).toEqual(["pf-test"]);
});
