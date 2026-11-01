import { expect, test } from "@playwright/test";
import { mockLearner, openDataset } from "./fixtures/learner";

test("a saved suggestion receipt does not claim a live activation state", async ({ page }) => {
  const state = await mockLearner(page);
  state.suggestions[0].status = "staged";
  await openDataset(page);
  const suggestion = page.getByRole("article", { name: "Suggestion modbus-1", exact: true });
  await expect(suggestion.getByText(/Saved—activation not verified/)).toBeVisible();
  await expect(suggestion).not.toContainText("not active yet");
});

test("collection disclosures retain exact destination, checksums and unknown reason codes", async ({ page }) => {
  await mockLearner(page);
  await page.route("**/api/v1/learn/generate", async (route) => {
    route.request().postDataJSON();
    await route.fulfill({ json: { suggestions: [], withheld: { future_reason_code: 7 } } });
  });
  await openDataset(page);
  const review = page.getByLabel("Dataset review");
  await expect(review.getByText("Changes will be saved to the pending configuration—not activated.")).toBeVisible();
  const destination = review.locator("details").filter({ has: page.getByText("Destination details", { exact: true }) });
  await expect(destination).toHaveJSProperty("open", false);
  await destination.locator("summary").focus();
  await page.keyboard.press("Enter");
  await expect(destination.getByText("Configuration version: 0123456789abcdef.1", { exact: true })).toBeVisible();
  const collection = review.locator("details").filter({ has: page.getByText("Collection details", { exact: true }) });
  await expect(collection).toHaveJSProperty("open", false);
  await collection.locator("summary").click();
  for (const raw of ["capture-sha", "evidence-sha", "decoder-1", "profile-1", "snapshot-1"]) {
    await expect(collection.getByText(raw, { exact: true })).toBeVisible();
  }
  await review.getByRole("button", { name: "Generate suggestions", exact: true }).click();
  const reason = review.getByRole("listitem").filter({ hasText: "Unrecognized reason: 7" });
  await expect(reason.getByText("Unrecognized reason: 7", { exact: true })).toBeVisible();
  await expect(reason.getByText("future_reason_code", { exact: true })).not.toBeVisible();
  await reason.locator("summary").click();
  await expect(reason.getByText("future_reason_code", { exact: true })).toBeVisible();
});

test("advanced capture settings and exact filter stay reachable and survive saving collapsed", async ({ page }) => {
  let saved: Record<string, unknown> | null = null;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const config = { snaplen: 128, interfaces: ["eth0"], filter: { proto: "tcp", port: "2404" }, bufferMB: 9, promisc: false };
    if (path === "/api/v1/pcap/config" && route.request().method() === "POST") {
      saved = route.request().postDataJSON();
      return route.fulfill({ json: saved, headers: { "X-Containd-Revision": "0123456789abcdef.2", "X-Containd-Config": "staged" } });
    }
    const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/pcap/config" ? config
      : path === "/api/v1/pcap/status" ? { running: false }
      : path === "/api/v1/interfaces" ? [{ name: "lan1", device: "eth0", zone: "lan" }]
      : path === "/api/v1/interfaces/state" ? [{ name: "eth0", up: true, addrs: [] }]
      : path === "/api/v1/zones" ? [{ name: "lan" }]
      : path === "/api/v1/pcap/list" ? []
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": saved ? "0123456789abcdef.2" : "0123456789abcdef.1" } });
  });
  await page.goto("/dataplane/");
  const advanced = page.locator("details").filter({ has: page.getByText("Advanced capture options", { exact: true }) });
  await expect(advanced).toHaveJSProperty("open", false);
  await advanced.locator("summary").click();
  const snaplen = advanced.locator("input[type=number]").first();
  await expect(snaplen).toBeVisible();
  await expect(snaplen).toHaveValue("128");
  await expect(advanced.locator("label").filter({ hasText: "Capture memory buffer (MB)" })).toBeVisible();
  await expect(advanced.locator("label").filter({ hasText: "Capture all traffic visible on the interface" })).toBeVisible();
  await advanced.locator("summary").click();
  const filter = page.locator("details").filter({ has: page.getByText("Capture filter (BPF)", { exact: true }) });
  await expect(filter).toHaveJSProperty("open", false);
  await filter.locator("summary").click();
  await expect(filter.locator("code")).toHaveText("tcp and port 2404");
  await page.getByRole("button", { name: "Save PCAP defaults", exact: true }).click();
  await expect.poll(() => saved).toMatchObject({ snaplen: 128, bufferMB: 9, promisc: false, filter: { proto: "tcp", port: "2404" } });
});
