import { expect, test, type Page } from "@playwright/test";

// Identity bindings live in the candidate: GET lists them as an array, POST
// stages one (replacing the address's binding) and DELETE stages a removal.

type Binding = { ip: string; identities: string[] };
type Seen = { posts: Binding[]; deletes: string[] };

async function mockAPI(
  page: Page,
  options: { role?: string; bindings?: Binding[]; rules?: unknown[]; postError?: string; listStatus?: number } = {},
): Promise<Seen> {
  const seen: Seen = { posts: [], deletes: [] };
  let bindings = options.bindings ?? [
    { ip: "10.0.0.5", identities: ["operator", "engineering"] },
    { ip: "2001:db8::7", identities: ["historian"] },
  ];
  await page.addInitScript((role) => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", role);
  }, options.role ?? "admin");
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/identities" && request.method() === "POST") {
      const body = request.postDataJSON() as Binding;
      seen.posts.push(body);
      if (options.postError) {
        await route.fulfill({ status: 400, json: { error: options.postError }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        return;
      }
      bindings = [...bindings.filter((b) => b.ip !== body.ip), body];
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
      return;
    }
    if (path.startsWith("/api/v1/identities/") && request.method() === "DELETE") {
      const ip = decodeURIComponent(path.slice("/api/v1/identities/".length));
      seen.deletes.push(ip);
      bindings = bindings.filter((b) => b.ip !== ip);
      await route.fulfill({ json: { deleted: ip }, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
      return;
    }
    if (path === "/api/v1/identities") {
      if (options.listStatus) {
        await route.fulfill({ status: options.listStatus, json: { error: "config store unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
        return;
      }
      await route.fulfill({ json: { mappings: bindings }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      body = { id: "u1", username: "containd", role: options.role ?? "admin" };
    }
    if (path === "/api/v1/firewall/rules") body = options.rules ?? [];
    if (path === "/api/v1/config/diff") body = { changed: true, changedSections: ["firewall"] };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return seen;
}

async function open(page: Page) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/identities");
  await page.goto("/identities/");
  await loaded;
}

const row = (page: Page, ip: string) =>
  page.getByRole("row").filter({ has: page.getByRole("cell", { name: ip, exact: true }) });

test("lists bindings and stages a new one", async ({ page }) => {
  const seen = await mockAPI(page);
  await open(page);
  await expect(row(page, "10.0.0.5")).toContainText("operator");
  await expect(row(page, "10.0.0.5")).toContainText("engineering");
  await expect(row(page, "2001:db8::7")).toContainText("historian");
  await expect(page.getByText("2 of 4096 bindings")).toBeVisible();

  await page.getByLabel("Address").fill("10.0.0.9");
  await page.getByLabel("Identities", { exact: true }).fill("vendor, contractor");
  await page.getByRole("button", { name: "Bind", exact: true }).click();
  await expect(row(page, "10.0.0.9")).toContainText("contractor");
  expect(seen.posts).toEqual([{ ip: "10.0.0.9", identities: ["vendor", "contractor"] }]);
  await expect(page.getByLabel("Address")).toHaveValue("");
});

test("checks the address and labels before staging", async ({ page }) => {
  const seen = await mockAPI(page);
  await open(page);
  await page.getByLabel("Address").fill("10.0.0.300");
  await page.getByLabel("Identities", { exact: true }).fill("ops");
  await page.getByRole("button", { name: "Bind", exact: true }).click();
  await expect(page.getByText('"10.0.0.300" is not an IPv4 or IPv6 address.')).toBeVisible();

  await page.getByLabel("Address").fill("10.0.0.6");
  await page.getByLabel("Identities", { exact: true }).fill("");
  await page.getByRole("button", { name: "Bind", exact: true }).click();
  await expect(page.getByText("An address needs 1 to 16 identities.")).toBeVisible();

  await page.getByLabel("Identities", { exact: true }).fill(Array.from({ length: 17 }, (_, i) => `l${i}`).join(","));
  await page.getByRole("button", { name: "Bind", exact: true }).click();
  await expect(page.getByText("An address needs 1 to 16 identities.")).toBeVisible();

  await page.getByLabel("Identities", { exact: true }).fill("x".repeat(65));
  await page.getByRole("button", { name: "Bind", exact: true }).click();
  await expect(page.getByText("must be 1 to 64 bytes")).toBeVisible();
  expect(seen.posts).toEqual([]);
});

test("an already bound address is replaced, and server errors surface", async ({ page }) => {
  const seen = await mockAPI(page, { postError: "firewall.identityBindings[0]: ip \"10.0.0.5\" must be a unicast IPv4 or IPv6 address without a zone" });
  await open(page);
  await page.getByLabel("Address").fill("10.0.0.5");
  await expect(page.getByRole("button", { name: "Replace binding" })).toBeVisible();
  await expect(page.getByText("This address is already bound; binding it replaces its identities.")).toBeVisible();
  await page.getByLabel("Identities", { exact: true }).fill("operator");
  await page.getByRole("button", { name: "Replace binding" }).click();
  await expect(page.getByText("must be a unicast IPv4 or IPv6 address without a zone")).toBeVisible();
  expect(seen.posts).toHaveLength(1);
});

test("edits a binding's labels in place and removes a binding", async ({ page }) => {
  const seen = await mockAPI(page);
  await open(page);
  await row(page, "2001:db8::7").getByRole("button", { name: "Edit", exact: true }).click();
  await page.getByLabel("Identities of 2001:db8::7").fill("historian, scada");
  await row(page, "2001:db8::7").getByRole("button", { name: "Save", exact: true }).click();
  await expect(row(page, "2001:db8::7")).toContainText("scada");
  expect(seen.posts).toEqual([{ ip: "2001:db8::7", identities: ["historian", "scada"] }]);

  await row(page, "2001:db8::7").getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("established ones that only such a rule allowed");
  await page.getByRole("dialog").getByRole("button", { name: "Remove", exact: true }).click();
  await expect(row(page, "2001:db8::7")).toHaveCount(0);
  expect(seen.deletes).toEqual(["2001:db8::7"]);
});

test("names rule identities that no address carries", async ({ page }) => {
  await mockAPI(page, {
    rules: [
      { id: "ops", action: "ALLOW", identities: ["operator"] },
      { id: "vendor-ssh", action: "ALLOW", identities: ["vendor", "contractor"] },
    ],
  });
  await open(page);
  await expect(page.getByRole("status", { name: "Unbound rule identities" })).toContainText("contractor, vendor");
  await expect(page.getByRole("status", { name: "Unbound rule identities" })).not.toContainText("operator");
});

test("view-only users see bindings without edit controls", async ({ page }) => {
  await mockAPI(page, { role: "view" });
  await open(page);
  await expect(row(page, "10.0.0.5")).toBeVisible();
  await expect(page.getByLabel("Address")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
});

test("an unreadable candidate reports why", async ({ page }) => {
  await mockAPI(page, { listStatus: 500 });
  await open(page);
  await expect(page.getByRole("alert", { name: "Identity bindings error" })).toContainText("Identity bindings unavailable: config store unavailable");
  await expect(page.getByText("No identity bindings")).toHaveCount(0);
});
