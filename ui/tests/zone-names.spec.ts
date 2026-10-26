import { expect, test, type Page } from "@playwright/test";

import { MAX_ZONE_NAME_BYTES, validateZoneName } from "../lib/validate";

// The server refuses a zone name that is blank, has leading or trailing
// whitespace, or is longer than 125 bytes of UTF-8. The zone form refuses
// the same names before saving and shows the server's error if one returns.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

async function openZones(page: Page, reply: { status: number; error?: string } = { status: 200 }) {
  const posts: unknown[] = [];
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      await route.fulfill({ json: user });
      return;
    }
    if (path === "/api/v1/zones" && request.method() === "POST") {
      posts.push(request.postDataJSON());
      await route.fulfill(reply.status === 200 ? { json: request.postDataJSON() } : { status: reply.status, json: { error: reply.error } });
      return;
    }
    await route.fulfill({ json: path === "/api/v1/zones" ? [] : {} });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/zones");
  await page.goto("/zones/");
  await loaded;
  return posts;
}

const nameField = (page: Page) => page.getByLabel("Zone name", { exact: true });
const create = (page: Page) => page.getByRole("button", { name: "Create", exact: true });
const nameError = (page: Page) => page.getByRole("alert", { name: "Zone name error" });

// "a" plus 62 two-byte characters: 125 bytes in 63 characters.
const atLimit = "a" + "é".repeat(62);
// 63 two-byte characters: 126 bytes in 63 characters.
const overLimit = "é".repeat(63);

for (const [label, value, message] of [
  ["blank", "   ", "Zone name is required."],
  ["leading whitespace", " ot", "Zone name cannot start or end with a space."],
  ["trailing whitespace", "ot ", "Zone name cannot start or end with a space."],
  ["over 125 bytes", overLimit, "Zone name is 126 bytes; the limit is 125 bytes"],
] as const) {
  test(`a ${label} zone name is refused before saving`, async ({ page }) => {
    const posts = await openZones(page);
    await nameField(page).fill(value);
    await expect(nameError(page)).toContainText(message);
    await create(page).click();
    await expect(nameError(page)).toContainText(message);
    expect(posts).toEqual([]);
  });
}

test("a multibyte zone name at exactly 125 bytes is saved as typed", async ({ page }) => {
  const posts = await openZones(page);
  await nameField(page).fill(atLimit);
  await expect(nameError(page)).toHaveCount(0);
  await create(page).click();
  await expect.poll(() => posts.length).toBe(1);
  expect(posts[0]).toMatchObject({ name: atLimit });
  await expect(page.getByRole("status", { name: "Notifications" })).toContainText("Zone staged");
});

test("a name the server still refuses shows the server's error", async ({ page }) => {
  const error = 'zone "ot" alias conflicts with zone name: ot';
  const posts = await openZones(page, { status: 400, error });
  await nameField(page).fill("ot");
  await create(page).click();
  await expect(page.getByRole("alert", { name: "Zone save error" })).toHaveText(error);
  expect(posts).toHaveLength(1);
});

test("zone name rules count UTF-8 bytes, not characters", () => {
  expect(new TextEncoder().encode(atLimit).length).toBe(MAX_ZONE_NAME_BYTES);
  expect(atLimit.length).toBe(63);
  expect(validateZoneName(atLimit)).toBeNull();
  expect(validateZoneName("z".repeat(125))).toBeNull();
  expect(validateZoneName("z".repeat(126))).toContain("126 bytes");
  expect(validateZoneName("ot ")).toContain("start or end with a space");
  expect(validateZoneName("ot.cell-1")).toBeNull();
  expect(validateZoneName("")).toBe("Zone name is required.");
});
