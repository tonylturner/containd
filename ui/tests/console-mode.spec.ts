import { expect, test } from "@playwright/test";

for (const width of [1280, 390]) {
  test(`configuration console preserves input and management login at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    let connections = 0;
    let changed = false;
    let unknown = false;
    let lastCommand = "";
    await page.route("**/api/v1/**", (route) => {
      const path = new URL(route.request().url()).pathname;
      const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
        ? { id: "admin", username: "operator", role: "admin" }
        : path.endsWith("/cli/ws/ticket") ? { ticket: "one-use", expiresIn: 30 }
        : path.endsWith("/cli/commands") ? ["show version", "help"]
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [], pendingConfirm: null }
        : {};
      return route.fulfill({ json });
    });
    await page.routeWebSocket("**/api/v1/cli/ws?*", (ws) => {
      connections += 1;
      const status = () => ({
        prompt: `containd(config${unknown ? "?" : changed ? "*" : ""})# `,
        status: `${unknown ? "Candidate status unavailable · 503" : changed ? "Pending changes" : "Candidate matches running"} · Shared candidate · Confirmation pending until 2030-01-01T00:00:00Z · Refreshed now`,
      });
      ws.send(JSON.stringify({ output: "Configuration CLI — lab-fw · operator/admin", ...status() }));
      ws.onMessage((message) => {
        const request = JSON.parse(String(message));
        if (request.control === "status") {
          ws.send(JSON.stringify({ control: "status", ...status() }));
        } else if (request.line === "exit") {
          ws.send(JSON.stringify({ control: "close", output: "Leaving configuration CLI." }));
        } else {
          lastCommand = request.line;
          ws.send(JSON.stringify({
            output: request.line === "show version" ? "containd 0.1.38"
              : request.line === "configure" ? "Already in configuration CLI."
              : "Session controls: exit",
            error: request.line === "pwd" ? "This is the configuration CLI, not Linux." : undefined,
            ...status(),
          }));
        }
      });
    });
    const loaded = page.waitForResponse("**/api/v1/dashboard");
    await page.goto("/");
    await loaded;
    await page.getByRole("button", { name: "CLI Console", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Configuration CLI", exact: true })).toBeVisible();
    await expect(page.getByText("Not an OS shell.", { exact: false })).toBeVisible();
    await expect(page.locator("#dashboard-console")).toContainText("Candidate matches running");
    const input = page.locator(".xterm-helper-textarea");
    await input.focus();
    await page.keyboard.type("conf");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Enter");
    await expect.poll(() => lastCommand).toBe("configure");
    await expect(page.locator(".xterm-rows")).toContainText("Already in configuration CLI");
    await page.keyboard.type("show vers");
    changed = true; // Another session stages an edit.
    await expect(page.locator("#dashboard-console")).toContainText("Pending changes", { timeout: 10000 });
    await page.keyboard.type("ion");
    await page.keyboard.press("Enter");
    await expect.poll(() => lastCommand).toBe("show version");
    expect(connections).toBe(1);
    await expect(page.locator(".xterm-rows")).toContainText("containd 0.1.38");
    await page.keyboard.type("pwd");
    await page.keyboard.press("Enter");
    await expect(page.locator(".xterm-rows")).toContainText("not Linux");
    unknown = true;
    await expect(page.locator("#dashboard-console")).toContainText("Candidate status unavailable", { timeout: 10000 });
    await expect(page.locator(".xterm-rows")).toContainText("containd(config?)#");
    await expect(page.locator("#dashboard-console")).toContainText("Confirmation pending until");
    expect(connections).toBe(1);
    await page.keyboard.type("exit");
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: "CLI Console", exact: true })).toHaveAttribute("aria-expanded", "false");
    await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "CLI Console", exact: true }).click();
    await expect(page.getByRole("button", { name: "Close console", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Close console", exact: true }).click();
    await expect(page.getByRole("button", { name: "CLI Console", exact: true })).toHaveAttribute("aria-expanded", "false");
    expect(connections).toBe(2);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}
