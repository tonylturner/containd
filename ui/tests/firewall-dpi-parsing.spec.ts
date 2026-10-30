import { expect, test, type Page } from "@playwright/test";

const protocols = [
  ["modbus", "Modbus/TCP"],
  ["dnp3", "DNP3"],
  ["cip", "CIP / EtherNet/IP"],
  ["iec104", "IEC 60870-5-104"],
] as const;

async function openEditor(
  page: Page,
  parsing?: Record<string, "tolerant" | "strict">,
  rejectSave = false,
) {
  const dataplane = {
    dpiEnabled: true,
    dpiMode: "enforce",
    dpiIcsProtocols: { dnp3: false },
    dpiProtocols: { http: false },
    nfqueueGroup: 101,
    ...(parsing ? { dpiIcsParsing: parsing } : {}),
  };
  const saves: Record<string, unknown>[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/dataplane" && request.method() === "POST") {
      const body = request.postDataJSON();
      saves.push(body);
      await route.fulfill(rejectSave
        ? { status: 400, json: { error: "parsing rejected" } }
        : { json: body });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      body = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
    }
    if (path === "/api/v1/firewall/rules" || path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = dataplane;
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane");
  await page.goto("/firewall/");
  await loaded;
  await configure(page);
  return { dataplane, saves };
}

async function configure(page: Page) {
  await page.getByText("ICS Protocol Decoders", { exact: true })
    .locator("xpath=../..")
    .getByRole("button", { name: "Configure", exact: true }).click();
}

function modal(page: Page) {
  return page.locator("div.fixed").filter({
    has: page.getByRole("heading", { name: "ICS Protocol DPI Configuration" }),
  });
}

test("missing parsing displays tolerant and saves without synthesizing defaults", async ({ page }) => {
  const { dataplane, saves } = await openEditor(page);
  for (const [, label] of protocols) {
    await expect(modal(page).getByLabel(`${label} parsing`)).toHaveValue("tolerant");
  }
  await expect(modal(page)).toContainText("Tolerant enforces what is decoded");
  await modal(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => saves.length).toBe(1);
  expect(saves[0]).toEqual(dataplane);
  expect(saves[0]).not.toHaveProperty("dpiIcsParsing");
  await expect(page.getByText("Staged — commit to apply.")).toBeVisible();
});

for (const [key, label] of protocols) {
  test(`${key} parsing saves only the changed key and preserves other settings`, async ({ page }) => {
    const other = key === "iec104" ? "modbus" : "iec104";
    const { dataplane, saves } = await openEditor(page, { [other]: "strict" });
    await expect(modal(page).getByLabel(`${label} parsing`)).toHaveValue("tolerant");
    await modal(page).getByLabel(`${label} parsing`).selectOption("strict");
    await modal(page).getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => saves.length).toBe(1);
    expect(saves[0]).toEqual({
      ...dataplane, dpiIcsParsing: { [other]: "strict", [key]: "strict" },
    });
    await configure(page);
    await expect(modal(page).getByLabel(`${label} parsing`)).toHaveValue("strict");
    await modal(page).getByLabel(`${label} parsing`).selectOption("tolerant");
    await modal(page).getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => saves.length).toBe(2);
    expect(saves[1]).toEqual({
      ...dataplane, dpiIcsParsing: { [other]: "strict", [key]: "tolerant" },
    });
  });
}

test("cancel leaves parsing untouched and a rejected save keeps the draft open", async ({ page }) => {
  const { saves } = await openEditor(page, { modbus: "strict" }, true);
  await modal(page).getByLabel("Modbus/TCP parsing").selectOption("tolerant");
  await modal(page).getByRole("button", { name: "Cancel", exact: true }).click();
  expect(saves).toEqual([]);
  await configure(page);
  await expect(modal(page).getByLabel("Modbus/TCP parsing")).toHaveValue("strict");
  await modal(page).getByLabel("Modbus/TCP parsing").selectOption("tolerant");
  await modal(page).getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Not saved: parsing rejected")).toBeVisible();
  await expect(modal(page).getByLabel("Modbus/TCP parsing")).toHaveValue("tolerant");
  await modal(page).getByRole("button", { name: "Cancel", exact: true }).click();
  await configure(page);
  await expect(modal(page).getByLabel("Modbus/TCP parsing")).toHaveValue("strict");
});
