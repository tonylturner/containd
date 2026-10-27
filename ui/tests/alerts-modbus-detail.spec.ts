import { expect, test, type Page } from "@playwright/test";

// The Modbus analysis of an alert shows the decoder's fields for the
// triggering message's function code: a written value for FC 5/6, the read
// and write ranges for FC 23, and the address range for quantity requests.

function modbusAlert(id: number, message: string, eventAttrs: Record<string, unknown>) {
  return {
    id, flowId: `flow-${id}`, proto: "ids", kind: "alert", timestamp: "2026-10-26T12:00:00Z",
    srcIp: "192.0.2.10", dstIp: "192.0.2.20", srcPort: 49152, dstPort: 502, transport: "tcp",
    attributes: { message, severity: "high", rule_id: `MB-${id}`, event_proto: "modbus", event_kind: "request", event_attrs: eventAttrs },
  };
}

const alerts = [
  modbusAlert(1, "coil write alert", { function_code: 5, unit_id: 1, is_write: true, address: 19, value: 0xff00 }),
  modbusAlert(2, "register write alert", { function_code: 6, unit_id: 1, is_write: true, address: 1, value: 3 }),
  modbusAlert(3, "read write alert", {
    function_code: 23, unit_id: 1, is_write: true, read_address: 3, read_quantity: 6,
    write_address: 14, write_quantity: 3, byte_count: 6,
  }),
  modbusAlert(4, "read alert", { function_code: 3, unit_id: 1, is_write: false, address: 11, quantity: 8 }),
];

async function openAlert(page: Page, message: string) {
  await page.getByRole("cell", { name: message, exact: true }).click();
  await expect(page.getByRole("heading", { name: message, exact: true })).toBeVisible();
}

function row(page: Page, label: string) {
  return page.locator("div.flex.justify-between").filter({ has: page.getByText(label, { exact: true }) });
}

test("modbus alert detail shows the fields of each function code", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path === "/api/v1/events" ? alerts
      : path.endsWith("/auth/me") || path.endsWith("/auth/session")
        ? { id: "admin", username: "containd", role: "admin" }
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json });
  });

  const answered = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/alerts/");
  await answered;

  await openAlert(page, "coil write alert");
  await expect(row(page, "Address")).toContainText("19 (0x0013)");
  await expect(row(page, "Value")).toContainText("0xff00 (ON)");
  await expect(page.getByText("Quantity", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Address Range", { exact: true })).toHaveCount(0);

  await openAlert(page, "register write alert");
  await expect(row(page, "Value")).toContainText("3 (0x0003)");

  await openAlert(page, "read write alert");
  await expect(row(page, "Read Range")).toContainText("3–8 (6 registers)");
  await expect(row(page, "Write Range")).toContainText("14–16 (3 registers)");
  await expect(page.getByText("Address Range", { exact: true })).toHaveCount(0);

  await openAlert(page, "read alert");
  await expect(row(page, "Start Address")).toContainText("11 (0x000b)");
  await expect(row(page, "Quantity")).toContainText("8 registers/coils");
  await expect(row(page, "Address Range")).toContainText("11–18");
  await expect(page.getByText("Value", { exact: true })).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});
