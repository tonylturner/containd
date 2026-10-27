import { expect, test, type Page } from "@playwright/test";

// useSaveAction refuses a second run while one is in flight even before
// React renders the pending state that disables the button. Two clicks
// dispatched in one task reach the handler with the button still enabled:
// no render happens between them, so only the hook's in-flight ref can stop
// the second save. The DNS service page saves through useSaveAction.

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

/** Mocks the API; DNS saves wait for the returned release(). */
async function mockAPI(page: Page) {
  let release!: () => void;
  const released = new Promise<void>((resolve) => { release = resolve; });
  const saves: unknown[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      await route.fulfill({ json: admin });
      return;
    }
    if (path === "/api/v1/services/dns" && request.method() !== "GET") {
      saves.push(request.postDataJSON());
      await released;
      await route.fulfill({ json: request.postDataJSON() });
      return;
    }
    const body = path === "/api/v1/services/dns" ? { enabled: true, listenPort: 53, upstreamServers: ["192.0.2.53"] }
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body });
  });
  return { saves, release };
}

test("two clicks before React renders save once", async ({ page }) => {
  const { saves, release } = await mockAPI(page);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/dns");
  await page.goto("/system/services/dns/");
  await loaded;
  const save = page.getByRole("button", { name: "Save", exact: true });
  await expect(save).toBeEnabled();

  // Both clicks run in this one task; React renders only after it returns.
  const enabledAtSecondClick = await save.evaluate((button: HTMLButtonElement) => {
    button.click();
    const enabled = !button.disabled;
    button.click();
    return enabled;
  });
  expect(enabledAtSecondClick).toBe(true);

  await expect(page.getByRole("button", { name: "Saving…" })).toBeDisabled();
  release();
  await expect(save).toBeEnabled();
  expect(saves).toHaveLength(1);
});
