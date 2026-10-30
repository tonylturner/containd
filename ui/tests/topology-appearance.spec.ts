import { expect, test } from "./fixtures/topology-test";

test.use({ viewport: { width: 1440, height: 900 } });

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    const data: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/config": {
        zones: [{ name: "it" }, { name: "ot" }, { name: "wan" }],
        interfaces: [],
        routing: { gateways: [], routes: [], rules: [] },
        firewall: { rules: [] },
      },
      "/api/v1/config/diff": { changed: false },
      "/api/v1/interfaces/state": [],
      "/api/v1/flows": [],
      "/api/v1/events": [],
    };
    return route.fulfill({ json: data[path] ?? {} });
  });
  const loaded = page.waitForResponse("**/api/v1/config");
  await page.goto("/topology/");
  await loaded;
  await expect(page.locator(".react-flow__node")).toHaveCount(6);
});

test("canvas controls retain their light buttons and contrasting icons", async ({ page }) => {
  const button = page.locator(".react-flow__controls-button").first();
  await expect(button).toHaveCSS("background-color", "rgb(254, 254, 254)");
  await expect(button.locator("svg")).toHaveCSS("fill", "rgb(0, 0, 0)");
  const sizes = await page.locator(".react-flow__controls-button").evaluateAll((buttons) =>
    buttons.map((el) => {
      const { width, height } = el.getBoundingClientRect();
      return { width, height };
    }));
  expect(sizes).toEqual(Array.from({ length: 3 }, () => ({ width: 26, height: 27 })));
  await button.hover();
  await expect(button).toHaveCSS("background-color", "rgb(244, 244, 244)");
  await expect(button.locator("svg")).toHaveCSS("fill", "rgb(0, 0, 0)");
});

test("canvas keeps its edges, hidden handles, selection glow and minimap", async ({ page }) => {
  const edges = page.locator(".react-flow__edge-path");
  await expect(edges).toHaveCount(5);
  for (const [index, stroke, width] of [
    [0, "rgba(107, 114, 128, 0.5)", "1px"],
    [1, "rgba(6, 182, 212, 0.5)", "1.5px"],
    [2, "rgba(34, 197, 94, 0.4)", "1.2px"],
    [4, "rgba(168, 85, 247, 0.4)", "1px"],
  ] as const) {
    await expect(edges.nth(index)).toHaveCSS("stroke", stroke);
    await expect(edges.nth(index)).toHaveCSS("stroke-width", width);
  }
  const node = page.locator('.react-flow__node[data-id="fw-main"]');
  await expect(node.locator(".react-flow__handle-top")).toHaveCSS("top", "-4px");
  await expect(node.locator(".react-flow__handle-bottom")).toHaveCSS("bottom", "-4px");
  for (const handle of await page.locator(".react-flow__handle").all()) {
    await expect(handle).toHaveCSS("opacity", "0");
  }
  await node.click();
  await page.mouse.move(0, 0);
  await expect(node.locator(":scope > div")).toHaveCSS("border-top-color", "rgba(245, 158, 11, 0.6)");
  await expect(node.locator(":scope > div")).toHaveCSS("box-shadow", "rgba(245, 158, 11, 0.12) 0px 0px 20px 0px");
  await expect(page.locator(".react-flow__minimap")).toHaveCSS("background-color", "rgb(10, 14, 10)");
  await expect(page.locator(".react-flow__minimap-mask")).toHaveCSS("fill", "rgba(6, 8, 8, 0.85)");
  await expect(page.locator(".react-flow__minimap-node")).toHaveCount(6);
  await expect(page.locator(".react-flow__attribution")).toHaveCount(0);
});
