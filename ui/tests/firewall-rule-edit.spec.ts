import { expect, test, type Page } from "@playwright/test";

// The rule editor sends a PATCH, which keeps every omitted key and merges
// nested objects: a field the user clears must be sent with its empty value,
// and a removed rate limit, schedule or ICS predicate as null.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const rule = {
  id: "plc-write",
  description: "Engineering writes",
  action: "ALLOW",
  log: true,
  sourceZones: ["it"],
  destZones: ["ot"],
  sources: ["10.10.0.5/32"],
  destinations: ["10.20.0.7/32"],
  protocols: [{ name: "tcp", port: "502" }],
  identities: ["engineering"],
  schedule: { daysOfWeek: ["Monday", "Friday"], startTime: "08:00", endTime: "17:00", timezone: "Europe/Berlin" },
  ics: { protocol: "modbus", functionCode: [16], mode: "enforce" },
};

type Seen = { patches: unknown[]; creates: unknown[] };

async function openFirewall(page: Page, rules: unknown[], dataplane: Record<string, unknown> = {}): Promise<Seen> {
  const seen: Seen = { patches: [], creates: [] };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/v1/firewall/rules/") && request.method() === "PATCH") {
      seen.patches.push(request.postDataJSON());
      await route.fulfill({ json: rules[0], headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    if (path === "/api/v1/firewall/rules" && request.method() === "POST") {
      seen.creates.push(request.postDataJSON());
      await route.fulfill({ json: request.postDataJSON(), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = rules;
    if (path === "/api/v1/zones") body = [{ name: "it" }, { name: "ot" }];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false, ...dataplane };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules");
  await page.goto("/firewall/");
  await loaded;
  return seen;
}

function editor(page: Page, id: string) {
  // The create form below repeats these fields; act in the editor only.
  return page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: `Edit rule ${id}` }) });
}

for (const field of ["description", "logging"] as const) {
  test(`editing only ${field} preserves every rule zone and protocol`, async ({ page }) => {
    const multi = {
      ...rule,
      sourceZones: ["it", "engineering"],
      destZones: ["ot", "safety"],
      protocols: [{ name: "tcp", port: "502" }, { name: "udp", port: "20000" }, { name: "icmp" }],
    };
    const seen = await openFirewall(page, [multi]);
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const form = editor(page, multi.id);
    if (field === "description") await form.getByPlaceholder("description").fill("Reviewed");
    else await form.getByLabel("Log hits").uncheck();
    await form.getByRole("button", { name: "Save changes" }).click();
    await expect.poll(() => seen.patches.length).toBe(1);
    expect(seen.patches[0]).toMatchObject({
      sourceZones: multi.sourceZones,
      destZones: multi.destZones,
      protocols: multi.protocols,
    });
  });
}

test("editing a rule with any protocol does not add a TCP restriction", async ({ page }) => {
  const seen = await openFirewall(page, [{ ...rule, protocols: [], ics: undefined }]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, rule.id);
  await form.getByPlaceholder("description").fill("Any protocol");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => seen.patches.length).toBe(1);
  expect(seen.patches[0]).toMatchObject({ protocols: [] });
});

test("clearing rule fields in the editor clears them", async ({ page }) => {
  const seen = await openFirewall(page, [rule]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  await form.getByPlaceholder("description").fill("");
  await form.getByLabel("Log hits").uncheck();
  await form.locator("select").filter({ hasText: "Source zone (any)" }).selectOption("");
  await form.locator("select").filter({ hasText: "Dest zone (any)" }).selectOption("");
  await form.getByPlaceholder("sources CIDR (csv)").fill("");
  await form.getByPlaceholder("destinations CIDR (csv)").fill(" ");
  await form.getByLabel("Identities").fill("");
  await form.getByLabel("Schedule", { exact: true }).uncheck();
  await form.getByLabel("ICS Protocol Filter").uncheck();
  await form.getByRole("button", { name: "Save changes" }).click();

  await expect.poll(() => seen.patches.length).toBe(1);
  expect(seen.patches[0]).toEqual({
    description: "",
    action: "ALLOW",
    log: false,
    sourceZones: [],
    destZones: [],
    sources: [],
    destinations: [],
    protocols: [{ name: "tcp", port: "502" }],
    identities: [],
    viaForwards: [],
    rateLimit: null,
    tag: "",
    schedule: null,
    ics: null,
  });
});

test("the editor keeps identities, schedule and an explicit ICS mode", async ({ page }) => {
  const seen = await openFirewall(page, [rule]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  await expect(form.getByLabel("Identities")).toHaveValue("engineering");
  await expect(form.getByLabel("Monday")).toBeChecked();
  await expect(form.getByLabel("Tuesday")).not.toBeChecked();
  await expect(form.getByLabel("Timezone")).toHaveValue("Europe/Berlin");
  await expect(form.getByLabel("Rule Mode")).toHaveValue("enforce");
  await form.getByRole("button", { name: "Save changes" }).click();

  await expect.poll(() => seen.patches.length).toBe(1);
  expect(seen.patches[0]).toMatchObject({
    action: "ALLOW",
    identities: ["engineering"],
    schedule: rule.schedule,
    rateLimit: null,
    tag: "",
    ics: { protocol: "modbus", functionCode: [16], mode: "enforce" },
  });
  // Editing never adds the create form's example addresses.
  expect(Object.hasOwn((seen.patches[0] as { ics: object }).ics, "addresses")).toBe(false);
});

test("an inherited ICS mode stays empty and names the global mode", async ({ page }) => {
  const inherit = { ...rule, ics: { protocol: "modbus", functionCode: [16] } };
  const seen = await openFirewall(page, [inherit], { dpiMode: "enforce" });
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  const mode = form.getByLabel("Rule Mode");
  await expect(mode).toHaveValue("");
  await expect(mode.locator("option:checked")).toHaveText("Inherit (Enforce)");
  await form.getByRole("button", { name: "Save changes" }).click();

  await expect.poll(() => seen.patches.length).toBe(1);
  const patch = seen.patches[0] as { ics: Record<string, unknown> };
  expect(patch.ics).toMatchObject({ protocol: "modbus", functionCode: [16] });
  expect(Object.hasOwn(patch.ics, "mode")).toBe(false);
});

test("choosing inherit clears a stored ICS mode", async ({ page }) => {
  const seen = await openFirewall(page, [rule]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  await form.getByLabel("Rule Mode").selectOption("");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => seen.patches.length).toBe(1);
  // Merge-PATCH null deletes the stored mode (config.PatchICSPredicate).
  expect(seen.patches[0]).toMatchObject({ ics: { protocol: "modbus", mode: null } });
});

test("RATE_LIMIT stages its limit and refuses an ICS protocol", async ({ page }) => {
  const seen = await openFirewall(page, [rule]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  await form.getByLabel("Action").selectOption("RATE_LIMIT");
  await expect(form).toContainText("Effect: drops the packets over the limit");
  await form.getByLabel("Packets per second").fill("0");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText("packets per second must be a whole number from 1 to 1000000");

  await form.getByLabel("Packets per second").fill("1000000");
  await form.getByLabel("Burst").fill("1000001");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText("burst must be a whole number from 0 to 1000000");

  await form.getByLabel("Burst").fill("20");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText("RATE_LIMIT rules take no ICS protocol");
  expect(seen.patches).toEqual([]);

  await form.getByLabel("ICS Protocol Filter").uncheck();
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => seen.patches.length).toBe(1);
  expect(seen.patches[0]).toMatchObject({
    action: "RATE_LIMIT",
    rateLimit: { packetsPerSecond: 1000000, burst: 20 },
    tag: "",
    ics: null,
  });
});

test("TAG validates its label and takes no schedule", async ({ page }) => {
  const seen = await openFirewall(page, [{ ...rule, ics: {} }]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  await form.getByLabel("Action").selectOption("TAG");
  await form.getByLabel("Tag", { exact: true }).fill("Eng Access");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText("Tag: use 1-32 characters");

  await form.getByLabel("Tag", { exact: true }).fill("eng-access");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText("a TAG rule takes no schedule");
  expect(seen.patches).toEqual([]);

  await form.getByLabel("Schedule", { exact: true }).uncheck();
  await expect(form.getByLabel("Schedule", { exact: true })).toBeDisabled();
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => seen.patches.length).toBe(1);
  expect(seen.patches[0]).toMatchObject({ action: "TAG", tag: "eng-access", rateLimit: null, schedule: null, ics: null });
});

test("schedules are checked before they are staged", async ({ page }) => {
  const seen = await openFirewall(page, [rule]);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = editor(page, "plc-write");
  await form.getByLabel("End time").fill("08:00");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText("Schedule: start and end times must differ.");
  await form.getByLabel("End time").fill("06:00");
  await form.getByLabel("Timezone").fill("Mars/Olympus");
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect(form).toContainText('"Mars/Olympus" is not an IANA timezone');
  expect(seen.patches).toEqual([]);

  // An end before the start is an overnight window.
  await form.getByLabel("Timezone").fill("");
  await form.getByLabel("Friday").uncheck();
  await form.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => seen.patches.length).toBe(1);
  expect(seen.patches[0]).toMatchObject({ schedule: { daysOfWeek: ["Monday"], startTime: "08:00", endTime: "06:00" } });
  expect(Object.hasOwn((seen.patches[0] as { schedule: object }).schedule, "timezone")).toBe(false);
});

test("the create form stages a RESET rule with identities and a schedule", async ({ page }) => {
  const seen = await openFirewall(page, [rule]);
  const form = page.locator("section").filter({ has: page.getByRole("heading", { name: "Create rule" }) });
  await form.getByPlaceholder("id (e.g. mb-allow)").fill("reset-ssh");
  await form.getByPlaceholder("port/range").fill("22");
  await form.getByLabel("Action").selectOption("RESET");
  await expect(form).toContainText("Rejects back to the sender");
  await form.getByLabel("Identities").fill("contractor, contractor");
  await form.getByRole("button", { name: "Create rule" }).click();
  await expect(form).toContainText('identity "contractor" is listed twice');

  await form.getByLabel("Identities").fill("contractor, vendor");
  await form.getByLabel("Schedule", { exact: true }).check();
  await form.getByLabel("Saturday").check();
  await form.getByLabel("Sunday").check();
  await form.getByRole("button", { name: "Create rule" }).click();
  await expect.poll(() => seen.creates.length).toBe(1);
  expect(seen.creates[0]).toEqual({
    id: "reset-ssh",
    position: "bottom",
    protocols: [{ name: "tcp", port: "22" }],
    identities: ["contractor", "vendor"],
    schedule: { daysOfWeek: ["Sunday", "Saturday"] },
    action: "RESET",
  });
});

test("the rule list tells deciding actions from effects and states precedence", async ({ page }) => {
  await openFirewall(page, [
    rule,
    { id: "reset-ssh", action: "RESET", protocols: [{ name: "tcp", port: "22" }] },
    { id: "pps-cap", action: "RATE_LIMIT", rateLimit: { packetsPerSecond: 100, burst: 20 } },
    { id: "label-eng", action: "TAG", tag: "eng-access", identities: ["engineering", "vendor"] },
  ]);
  await expect(page.getByText(/Among enforcing rules, the first matching terminal rule in list order decides/)).toBeVisible();
  await expect(page.getByText(/Monitor ICS rules never decide/)).toBeVisible();
  const row = (id: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name: id, exact: true }) });
  await expect(row("reset-ssh").getByText("RESET", { exact: true })).toHaveClass(/badge-critical/);
  await expect(row("reset-ssh").getByText("effect", { exact: true })).toHaveCount(0);
  await expect(row("pps-cap").getByText("RATE_LIMIT", { exact: true })).toHaveClass(/badge-warning/);
  await expect(row("pps-cap")).toContainText("effect");
  await expect(row("pps-cap")).toContainText("100 pps, burst 20");
  await expect(row("label-eng")).toContainText("eng-access");
  await expect(row("label-eng")).toContainText("identity engineering, vendor");
  await expect(row("plc-write")).toContainText("schedule Mon,Fri 08:00-17:00 Europe/Berlin");
});
