import { expect, test, type Page } from "@playwright/test";

// Until the first answer, the templates and NAT pages show they are loading
// rather than an empty list, disabled NAT or setup tips that read as
// confirmed. NAT settings the server did not return are reported, not shown
// as disabled.

type Reply = { status?: number; json: unknown };

/** Serves the API; the held path answers only after release(). */
async function serve(page: Page, held: string, replies: Record<string, Reply>) {
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === held) await gate;
    const reply = replies[path];
    if (reply) {
      await route.fulfill({ status: reply.status ?? 200, json: reply.json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return () => release();
}

function watchErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  return errors;
}

const answered = (page: Page, path: string) =>
  page.waitForResponse((r) => new URL(r.url()).pathname === path);
const requested = (page: Page, path: string) =>
  page.waitForRequest((r) => new URL(r.url()).pathname === path);

test("templates show loading, not 'No templates available', until the first list answers", async ({ page }) => {
  const errors = watchErrors(page);
  const release = await serve(page, "/api/v1/templates/ics", {
    "/api/v1/templates/ics": { json: [] },
    "/api/v1/zones": { json: [] },
  });
  const asked = requested(page, "/api/v1/templates/ics");
  await page.goto("/templates/");
  await asked;
  await expect(page.locator("main .animate-pulse").first()).toBeVisible();
  await expect(page.getByText("No templates available.", { exact: false })).toHaveCount(0);

  const done = answered(page, "/api/v1/templates/ics");
  release();
  await done;
  await expect(page.getByText("No templates available.", { exact: false })).toBeVisible();
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("NAT shows loading, not disabled settings or setup tips, until the first answer", async ({ page }) => {
  const errors = watchErrors(page);
  const release = await serve(page, "/api/v1/firewall/nat", {
    "/api/v1/firewall/nat": { json: { enabled: true, egressZone: "wan", portForwards: [] } },
    "/api/v1/zones": { json: [{ name: "wan" }, { name: "lan" }] },
  });
  const asked = requested(page, "/api/v1/firewall/nat");
  await page.goto("/nat/");
  await asked;
  await expect(page.locator("main .animate-pulse").first()).toBeVisible();
  await expect(page.getByText("No port forwards configured.", { exact: false })).toHaveCount(0);
  await expect(page.getByText("DISABLED", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Create zones first", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Enable SNAT for outbound access", { exact: true })).toHaveCount(0);

  const done = answered(page, "/api/v1/firewall/nat");
  release();
  await done;
  await expect(page.getByText("ENABLED", { exact: true })).toBeVisible();
  await expect(page.getByText("No port forwards configured.", { exact: false })).toBeVisible();
  await expect(page.getByText("Create zones first", { exact: true })).toHaveCount(0);
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("NAT reports settings the server did not return instead of showing them disabled", async ({ page }) => {
  const errors = watchErrors(page);
  await serve(page, "", {
    "/api/v1/firewall/nat": { status: 500, json: { error: "boom" } },
    "/api/v1/zones": { json: [{ name: "wan" }] },
  });
  const done = answered(page, "/api/v1/firewall/nat");
  await page.goto("/nat/");
  await done;
  await expect(page.getByRole("alert").filter({ hasText: "NAT settings unavailable" })).toBeVisible();
  await expect(page.getByText("DISABLED", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Save NAT" })).toHaveCount(0);
  await expect(page.getByText("No port forwards configured.", { exact: false })).toHaveCount(0);
  await expect(page.getByText("Enable SNAT for outbound access", { exact: true })).toHaveCount(0);
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  expect(errors).toEqual([]);
});
