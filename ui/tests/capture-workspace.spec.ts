import { expect, test } from "@playwright/test";

for (const forwarding of [false, true]) {
  test(`capture tasks retain live state, replay warnings and ${forwarding ? "saved" : "optional"} forwarding`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 1000 });
    const writes: unknown[] = [];
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (route.request().method() !== "GET") writes.push(route.request().postDataJSON());
      const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
        : path === "/api/v1/pcap/config" ? {
          interfaces: ["eth0"], snaplen: 262144, maxSizeMB: 64, maxFiles: 8,
          mode: "rolling", bufferMB: 4, promisc: true, rotateSeconds: 300, filePrefix: "capture",
          forwardTargets: forwarding ? [{ interface: "eth0", enabled: true, host: "sensor.local", port: 9000, proto: "udp" }] : [],
        }
        : path === "/api/v1/pcap/status" ? { running: true, interfaces: ["live0"], startedAt: "2026-11-01T12:00:00Z" }
        : path === "/api/v1/interfaces" ? [{ name: "lan", device: "eth0", zone: "lan" }]
        : path === "/api/v1/interfaces/state" ? [{ name: "eth0", up: true }]
        : path === "/api/v1/zones" ? [{ name: "lan" }]
        : path === "/api/v1/pcap/list" ? [{ name: "incident.pcap", interface: "eth0", createdAt: "2026-11-01T12:00:00Z", sizeBytes: 4096, status: "ready" }]
        : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
      await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    await page.goto("/dataplane/");
    const capture = page.getByRole("region", { name: "Capture now", exact: true });
    await expect(capture.getByText("live0", { exact: true })).toBeVisible();
    await expect(capture.getByText("Running", { exact: true })).toBeVisible();
    await capture.getByRole("button", { name: "None", exact: true }).click();
    await expect(capture.getByText("live0", { exact: true })).toBeVisible();
    await expect(capture.getByText(/Form settings \(not live\): no interfaces or zones/)).toBeVisible();
    const toggle = capture.getByRole("button", { name: "PCAP Forwarding (Remote Sensor)", exact: true });
    await expect(toggle).toHaveAttribute("aria-expanded", String(forwarding));
    if (forwarding) {
      await expect(capture.locator('input[value="sensor.local"]')).toBeVisible();
      await toggle.click();
      await expect(capture.getByText(/Configured forwarding: eth0/)).toBeVisible();
    }
    await toggle.focus();
    await page.keyboard.press("Enter");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(toggle).toBeFocused();
    for (const section of ["Saved captures", "Replay to a network"]) {
      await expect(page.getByRole("region", { name: section, exact: true })).toContainText("Replay transmits traffic onto the selected network immediately. It is not offline analysis.");
    }
    await expect(page.getByRole("link", { name: "Analyze captures offline" })).toHaveAttribute("href", "/pcap/");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    expect(writes).toEqual([]);
  });
}
