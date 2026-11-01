import { expect, test } from "./fixtures/topology-test";
import canvasFixture from "./fixtures/topology-canvas.json";

const responses: Record<string, unknown> = canvasFixture;
const edgeIds = ["e-internet-gw", "e-gw-fw", "e-fw-zone-it", "e-fw-zone-ot", "e-fw-zone-wan"];

for (const width of [1440, 1024]) {
  test(`all logical edges survive 10 cold loads at ${width}px`, async ({ browser, baseURL }) => {
    test.setTimeout(180_000);
    for (let iteration = 1; iteration <= 10; iteration++) {
      await test.step(`load ${iteration}`, async () => {
        const context = await browser.newContext({ baseURL, viewport: { width, height: 900 } });
        try {
          const page = await context.newPage();
          const errors: string[] = [];
          const typeWarnings: string[] = [];
          page.on("pageerror", (error) => errors.push(error.message));
          page.on("console", (message) => {
            if (message.text().includes("reactflow.dev/error#002")) typeWarnings.push(message.text());
          });
          await page.route("**/api/v1/**", (route) =>
            route.fulfill({ json: responses[new URL(route.request().url()).pathname] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
          const loaded = page.waitForResponse("**/api/v1/config");
          await page.goto("/topology/");
          await loaded;
          await expect(page.locator(".react-flow__node")).toHaveCount(6);
          await expect(page.locator(".react-flow__edge-path")).toHaveCount(edgeIds.length);
          for (const id of edgeIds) {
            const path = page.locator(`.react-flow__edge[data-id="${id}"] .react-flow__edge-path`);
            await expect(path).toHaveAttribute("d", /^M.+L.+/);
          }
          // Let fonts and initial fitting settle without interacting with or
          // refreshing the canvas: neither may be needed to recover its edges.
          await page.evaluate(() => document.fonts.ready);
          await page.waitForTimeout(1200);
          await expect(page.locator(".react-flow__edge-path")).toHaveCount(edgeIds.length);
          expect(errors).toEqual([]);
          expect(typeWarnings).toEqual([]);
        } finally {
          await context.close();
        }
      });
    }
  });
}

test("topology refresh updates data without resetting measured, selected or dragged nodes", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const updatedResponses = structuredClone(responses);
  await page.route("**/api/v1/**", (route) =>
    route.fulfill({ json: updatedResponses[new URL(route.request().url()).pathname] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/topology/");
  const edges = page.locator(".react-flow__edge-path");
  await expect(edges).toHaveCount(edgeIds.length);
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(1200);
  const node = page.locator('.react-flow__node[data-id="fw-main"]');
  await node.click();
  const box = await node.boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
  await page.mouse.down();
  await page.mouse.move(box!.x + box!.width / 2 + 40, box!.y + box!.height / 2 + 30, { steps: 5 });
  await page.mouse.up();
  const draggedTransform = await node.evaluate((el) => el.style.transform);
  updatedResponses["/api/v1/flows"] = [{ flowId: "flow-1", srcIp: "192.0.2.10", dstIp: "198.51.100.10" }];
  const refreshed = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/flows");
  await page.getByTitle("Refresh", { exact: true }).click();
  await refreshed;
  await expect(node).toContainText("sessions1");
  await expect(node).toHaveClass(/\bselected\b/);
  await expect.poll(() => node.evaluate((el) => el.style.transform)).toBe(draggedTransform);
  await expect(edges).toHaveCount(edgeIds.length);
  // Native selection drives the custom card without cloning every controlled
  // node; deselection must keep the detail panel and the card in agreement.
  await page.locator(".react-flow__pane").click({ position: { x: 80, y: 200 } });
  await expect(node).not.toHaveClass(/\bselected\b/);
  await expect(page.getByText("Select any node to inspect its state", { exact: false })).toBeVisible();
});
