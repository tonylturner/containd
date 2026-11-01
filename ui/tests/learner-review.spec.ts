import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { mockLearner, openDataset, suggestion } from "./fixtures/learner";

const pending = "Saved changes are not active yet.";

test("selection starts empty, Generate is explicit, scope and frozen proof are visible", async ({
  page,
}) => {
  const state = await mockLearner(page);
  await page.goto("/pcap/");
  await page
    .getByLabel("Existing PCAP Files")
    .getByRole("button", { name: "Analyze", exact: true })
    .click();
  await expect(page.getByLabel("Dataset review")).toBeVisible();
  expect(state.writes.map((w) => w.path)).toEqual([
    "/pcap/analyze/example.pcap",
  ]);
  await expect(
    page.getByRole("button", { name: "Stage 0 selected", exact: true }),
  ).toBeDisabled();
  await expect(
    page.getByLabel("Select modbus-1", { exact: true }),
  ).not.toBeChecked();
  await page
    .getByRole("button", { name: "Generate suggestions", exact: true })
    .click();
  await expect(
    page.getByText(
      "IEC command withheld: value not expressible: 3",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    page.getByLabel("Select modbus-1", { exact: true }),
  ).not.toBeChecked();
  const modbus = page.getByRole("article", {
    name: "Suggestion modbus-1",
    exact: true,
  });
  const emptyStage = page.getByRole("button", {
    name: "Stage 0 selected",
    exact: true,
  });
  await expect(emptyStage).toBeDisabled();
  await expect(emptyStage).toHaveCSS("cursor", "not-allowed");
  await expect(emptyStage).toHaveCSS("opacity", "0.3");
  await expect(emptyStage).toHaveClass(/bg-\(--surface2\)/);
  await expect(modbus).toContainText("unitId=0");
  await expect(modbus).toContainText("10-11");
  const evidence = modbus.getByLabel("Frozen certification");
  await expect(evidence).toHaveJSProperty("open", false);
  await expect(evidence.locator("summary")).toContainText(
    "replay 24/24 · boundaries 16/16",
  );
  await expect(evidence.getByLabel("Certification warnings")).toHaveClass(
    /text-\(--amber\)/,
  );
  await expect(evidence.getByLabel("Certification warnings")).toHaveText(
    "Supported selector relations only; not transaction equality.",
  );
  await expect(modbus.getByText(/transaction equality/)).toHaveCount(1);
  await expect(
    modbus.getByText("Evidence checksum: evidence-sha", { exact: true }),
  ).not.toBeVisible();
  await evidence.locator("summary").click();
  await expect(
    modbus.getByText("Evidence checksum: evidence-sha", { exact: true }),
  ).toBeVisible();
  await modbus
    .getByRole("button", { name: "Preview live recent evidence" })
    .click();
  await expect(modbus.getByLabel("Rule impact preview")).toContainText(
    "1 of 2 recent events",
  );
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
});

test("IEC requires separate admin review and then deliberate selection", async ({
  page,
}) => {
  const state = await mockLearner(page);
  await openDataset(page);
  const iec = page.getByRole("article", {
    name: "Suggestion iec-1",
    exact: true,
  });
  await expect(
    iec.getByRole("checkbox", { name: "Select iec-1", exact: true }),
  ).toBeDisabled();
  await expect(iec).toContainText("monitor, never enforce");
  await expect(iec.getByLabel("Proposed rules")).toContainText("execute state SCS 1 (on) QU 0");
  const dir = process.env.IEC_PRED_SCREENSHOTS;
  if (dir) {
    await mkdir(dir, { recursive: true });
    await iec.screenshot({ path: `${dir}/iec104-review-card.png`, style: "nextjs-portal { display: none !important; }" });
  }
  await iec.getByRole("button", { name: "Review and approve" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Review", exact: true })
    .click();
  await expect(
    iec.getByRole("checkbox", { name: "Select iec-1", exact: true }),
  ).toBeEnabled();
  await expect(
    iec.getByRole("checkbox", { name: "Select iec-1", exact: true }),
  ).not.toBeChecked();
  expect(state.writes).toEqual([
    {
      path: "/learn/suggestions/iec-1/review",
      body: {
        selection: { id: "iec-1", revision: 2 },
        approve: true,
        coordinateApproved: false,
      },
    },
  ]);
  await expect(iec).toContainText("COT 6 OA 0 P/N=0 T=0");
  await expect(iec.getByLabel("Proposed rules")).toContainText("state SCS 1 (on) QU 0");
});

test("wire-coordinate approval cannot be replaced by selection", async ({
  page,
}) => {
  const state = await mockLearner(page);
  state.suggestions[0].content.requiresCoordinateReview = true;
  await openDataset(page);
  const modbus = page.getByRole("article", {
    name: "Suggestion modbus-1",
    exact: true,
  });
  await expect(
    modbus.getByLabel("Select modbus-1", { exact: true }),
  ).toBeDisabled();
  await expect(
    modbus.getByRole("button", { name: "Review and approve" }),
  ).toBeDisabled();
  await modbus
    .getByLabel(
      "I verified the captured addresses and service against the policy and NAT settings.",
    )
    .check();
  await modbus.getByRole("button", { name: "Review and approve" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Review", exact: true })
    .click();
  await expect(
    modbus.getByLabel("Select modbus-1", { exact: true }),
  ).toBeEnabled();
  expect(state.writes[0].body.coordinateApproved).toBe(true);
});

test("409 is atomic: keeps selections but drops the receipt and unchecks changed suggestions", async ({
  page,
}) => {
  const state = await mockLearner(page);
  state.suggestions = [suggestion(), suggestion("modbus-2")];
  state.conflict = true;
  await openDataset(page);
  const before = state.suggestionReads;
  await page.getByLabel("Select modbus-1", { exact: true }).check();
  await page.getByLabel("Select modbus-2", { exact: true }).check();
  await page
    .getByRole("button", { name: "Stage 2 selected", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Stage", exact: true })
    .click();
  await expect(
    page.getByLabel("Dataset review").getByRole("alert"),
  ).toContainText("candidate rule conflict: no selected rules staged");
  await expect.poll(() => state.suggestionReads).toBeGreaterThan(before);
  expect(state.writes).toHaveLength(1);
  expect(state.writes[0]).toMatchObject({
    path: "/learn/apply",
    body: {
      selections: [
        { id: "modbus-1", revision: 2 },
        { id: "modbus-2", revision: 2 },
      ],
    },
  });
  await expect(
    page.getByRole("article", { name: "Suggestion modbus-1", exact: true }),
  ).toContainText("Suggestion version 3");
  await expect(
    page.getByRole("button", { name: "Stage 1 selected", exact: true }),
  ).toBeEnabled();
  await expect(page.getByLabel("Select modbus-1", { exact: true })).not.toBeChecked();
  await expect(page.getByLabel("Select modbus-2", { exact: true })).toBeChecked();
  await expect(page.getByText("Changed since selected — review this revision and select it again.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toHaveCount(0);
  state.conflict = false;
  await page.getByLabel("Select modbus-1", { exact: true }).check();
  await page.getByRole("button", { name: "Stage 2 selected", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText(/2 suggestion\(s\) staged — not active/)).toBeVisible();
  expect(state.writes[1].body.selections).toEqual([{ id: "modbus-1", revision: 3 }, { id: "modbus-2", revision: 2 }]);
});

test("uncertain completion retries identical request ID and ordered revisions", async ({
  page,
}) => {
  const state = await mockLearner(page);
  state.uncertain = true;
  await openDataset(page);
  await page.getByLabel("Select modbus-1", { exact: true }).check();
  await page
    .getByRole("button", { name: "Stage 1 selected", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Stage", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Retry same staging request" }),
  ).toBeVisible();
  const steps = page.getByRole("navigation", { name: "Learner steps" });
  await expect(steps.getByRole("button", { name: "4 Stage", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: /^Stage \d+ selected$/ })).toBeDisabled();
  await expect(steps).toContainText("Resolve the retained staging receipt; retry uses the identical request.");
  await expect(page.getByRole("button", { name: "Generate suggestions", exact: true })).toBeDisabled();
  state.uncertain = false;
  await page.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await page
    .getByRole("button", { name: "Retry same staging request" })
    .click();
  await expect(
    page.getByText(/1 suggestion\(s\) staged — not active/),
  ).toBeVisible();
  expect(state.writes[1]).toEqual(state.writes[0]);
});

test("viewer reads proof and authority but has no mutation or selection actions", async ({
  page,
}) => {
  const state = await mockLearner(page, "view");
  await openDataset(page);
  await expect(
    page
      .locator("summary")
      .filter({ hasText: "Checks on saved evidence" })
      .first(),
  ).toBeVisible();
  for (const name of [
    /Analyze/,
    /^Generate suggestions$/,
    /Start watch/,
    /Stop watch/,
    /Review and approve/,
    /Reject/,
    /Stage \d/,
    /Preview live/,
  ])
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  const steps = page.getByRole("navigation", { name: "Learner steps" });
  for (const [name, section] of [
    ["2 Generate", "Generate from collection"],
    ["3 Review", "Review suggestions"],
    ["4 Stage", "Stage reviewed suggestions"],
  ]) {
    const step = steps.getByRole("button", { name, exact: true });
    await expect(step).toBeEnabled();
    await step.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("region", { name: section, exact: true })).toBeFocused();
  }
  await page.getByRole("button", { name: "Inspect service authority" }).click();
  await expect(page.getByLabel("Service authority")).toContainText(
    "logical · verified",
  );
  expect(state.writes).toEqual([]);
});

test("bounded live watch start and stop seal a dataset in the same list", async ({
  page,
}) => {
  const state = await mockLearner(page);
  await page.goto("/pcap/");
  await page.getByRole("tab", { name: "Import capture", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByRole("tab", { name: "Watch live", exact: true })).toBeFocused();
  await page.getByRole("button", { name: "Start watch", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Start watch", exact: true }),
  ).toBeDisabled();
  await expect(page.getByLabel("Dataset review")).toContainText(
    "live · collecting",
  );
  await expect(
    page.getByRole("button", { name: "Generate suggestions", exact: true }),
  ).toBeDisabled();
  await page.getByRole("button", { name: "Stop watch", exact: true }).click();
  await expect(page.getByLabel("Dataset review")).toContainText(
    "live · sealed",
  );
  await expect(
    page.getByRole("button", { name: "Generate suggestions", exact: true }),
  ).toBeEnabled();
  expect(state.writes).toEqual([
    { path: "/learn/watches", body: { durationSeconds: 3600 } },
    { path: "/learn/watches/watch-1/stop", body: {} },
  ]);
});

test("expired and uncertified suggestions cannot be selected", async ({
  page,
}) => {
  const state = await mockLearner(page);
  state.suggestions[0].expiresAt = new Date(Date.now() - 1000).toISOString();
  delete state.suggestions[1].proof;
  await openDataset(page);
  await expect(
    page.getByLabel("Select modbus-1", { exact: true }),
  ).toBeDisabled();
  await expect(page.getByLabel("Select iec-1", { exact: true })).toBeDisabled();
});

test("the evidence poll expires selected suggestions and generation together", async ({
  page,
}) => {
  const now = Date.now();
  await page.clock.install({ time: now });
  const state = await mockLearner(page);
  const expiresAt = new Date(now + 5000).toISOString();
  state.datasets[0].expiresAt = expiresAt;
  state.suggestions[0].expiresAt = expiresAt;
  await openDataset(page);
  const select = page.getByLabel("Select modbus-1", { exact: true });
  const generate = page.getByRole("button", {
    name: "Generate suggestions",
    exact: true,
  });
  await select.check();
  await expect(generate).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Stage 1 selected", exact: true }),
  ).toBeEnabled();

  const refreshed = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/learn/datasets",
  );
  await page.clock.fastForward(10000);
  await refreshed;
  await expect(select).toBeDisabled();
  await expect(generate).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Stage 0 selected", exact: true }),
  ).toBeDisabled();
  expect(state.writes).toEqual([]);
});

test("collapsed certification keeps failures and every limitation visible", async ({
  page,
}) => {
  const state = await mockLearner(page);
  const suggestion = state.suggestions[0];
  suggestion.proof!.negative.passed--;
  suggestion.proof!.negative.failed++;
  suggestion.content.limits = [
    "NAT mapping must be verified.",
    "Finite boundary coverage.",
  ];
  suggestion.content.withheld = ["Unexpressible values withheld."];
  await openDataset(page);
  const modbus = page.getByRole("article", {
    name: "Suggestion modbus-1",
    exact: true,
  });
  const evidence = modbus.getByLabel("Frozen certification");
  await expect(evidence).toHaveJSProperty("open", false);
  const summary = evidence.locator("summary");
  await expect(summary).toContainText("replay 24/24 · boundaries 15/16");
  const warnings = summary.getByLabel("Certification warnings");
  await expect(warnings).toBeVisible();
  await expect(warnings).toHaveClass(/text-\(--amber\)/);
  for (const text of [
    "1 replay failure(s).",
    ...suggestion.content.limits,
    ...suggestion.content.withheld,
  ]) {
    await expect(warnings).toContainText(text);
  }
  await expect(
    modbus.getByLabel("Select modbus-1", { exact: true }),
  ).toBeDisabled();
});

test("390px dataset cards keep long identifiers and gaps within the page", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  const state = await mockLearner(page);
  state.datasets[0].id = "a".repeat(64);
  state.datasets[0].gaps = ["admission-loss-".repeat(20)];
  await page.goto("/pcap/");
  const datasets = page.getByLabel("Dataset list", { exact: true });
  await expect(
    datasets.getByRole("button", {
      name: `Open ${state.datasets[0].id}`,
      exact: true,
    }),
  ).toBeVisible();
  expect(
    await datasets.evaluate((el) => el.scrollWidth <= el.clientWidth),
  ).toBe(true);
  expect(
    await page.evaluate(
      () =>
        document.documentElement.scrollWidth <=
        document.documentElement.clientWidth,
    ),
  ).toBe(true);
});

for (const width of [1440, 390])
  for (const colorScheme of ["light", "dark"] as const) {
    test(`PCAP review fits ${width}px with ${colorScheme} preference`, async ({
      page,
    }) => {
      await page.setViewportSize({ width, height: 1000 });
      await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
      await mockLearner(page);
      await openDataset(page);
      await expect(page.getByLabel("Dataset review")).toBeVisible();
      expect(
        await page.evaluate(
          () =>
            document.documentElement.scrollWidth <=
            document.documentElement.clientWidth,
        ),
      ).toBe(true);
      if (width === 390) {
        const datasets = page.getByLabel("Dataset list", { exact: true });
        await expect(datasets.getByRole("table")).toHaveCount(0);
        for (const label of [
          "Dataset",
          "Source",
          "State",
          "Records / bytes",
          "Gaps",
          "Expires",
        ]) {
          await expect(
            datasets
              .getByRole("term")
              .filter({ hasText: new RegExp(`^${label}$`) }),
          ).toBeVisible();
        }
        expect(
          await datasets.evaluate((el) => el.scrollWidth <= el.clientWidth),
        ).toBe(true);
      }
      const dir = process.env.LEARNER_SCREENSHOTS;
      if (dir) {
        await mkdir(dir, { recursive: true });
        await page.screenshot({
          path: `${dir}/pcap-${width}-${colorScheme}.png`,
          fullPage: true,
          // Hide development chrome only during capture; never alter app config.
          style: "nextjs-portal { display: none !important; }",
        });
      }
    });
  }

for (const status of [400, 403, 422]) {
  test(`definitive learner ${status} drops only the receipt`, async ({ page }) => {
    await mockLearner(page);
    await page.route("**/api/v1/learn/apply", async route => {
      route.request().postDataJSON();
      await route.fulfill({ status, json: { error: "not persisted" } });
    });
    await openDataset(page);
    const select = page.getByLabel("Select modbus-1", { exact: true });
    await select.check();
    await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
    await expect(page.getByText("not persisted", { exact: true })).toBeVisible();
    await expect(select).toBeChecked();
    await expect(select).toBeEnabled();
    await expect(page.getByRole("button", { name: "Retry same staging request" })).toHaveCount(0);
    await select.uncheck();
    await expect(page.getByRole("button", { name: "Stage 0 selected", exact: true })).toBeDisabled();
  });
}

test("uncertain network staging keeps a receipt until explicit discard, without undoing the candidate", async ({ page }) => {
  await mockLearner(page);
  await page.route("**/api/v1/learn/apply", async route => {
    route.request().postDataJSON();
    await route.abort("failed");
  });
  await openDataset(page);
  const select = page.getByLabel("Select modbus-1", { exact: true });
  await select.check();
  await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toBeDisabled();
  await expect(select).toBeChecked();
  await expect(select).toBeDisabled();
  await page.getByRole("button", { name: "Discard receipt", exact: true }).click();
  await expect(page.getByRole("button", { name: "Retry same staging request" })).toHaveCount(0);
  await expect(select).toBeEnabled();
  await expect(page.getByText(/Receipt discarded. This does not undo any rules already staged/)).toBeVisible();
});


test("learner steps explain action prerequisites without disabling inspection or running actions", async ({ page }) => {
  const state = await mockLearner(page);
  state.suggestions = [];
  await page.goto("/pcap/");
  const steps = page.getByRole("navigation", { name: "Learner steps" });
  await expect(steps.getByRole("button", { name: "2 Generate", exact: true })).toBeDisabled();
  await expect(steps).toContainText("Open a dataset after collecting evidence.");
  await page.getByRole("button", { name: "Open capture-1", exact: true }).click();
  await expect(page.getByText("No retained suggestions.", { exact: false })).toBeVisible();
  await expect(steps.getByRole("button", { name: "2 Generate", exact: true })).toBeEnabled();
  await expect(steps.getByRole("button", { name: "3 Review", exact: true })).toBeEnabled();
  await expect(steps).toContainText("Generate suggestions explicitly after collection finishes.");
  await expect(steps.getByRole("button", { name: "4 Stage", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: /^Stage \d+ selected$/ })).toBeDisabled();
  await expect(steps).toContainText("Review and select eligible suggestions first.");
  await steps.getByRole("button", { name: "2 Generate", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("region", { name: "Generate from collection" })).toBeFocused();
  expect(state.writes).toEqual([]);
});

test("expired dataset explains why Generate is disabled and preserves inspection", async ({ page }) => {
  const state = await mockLearner(page);
  state.datasets[0].expiresAt = new Date(Date.now() - 1000).toISOString();
  await openDataset(page);
  const steps = page.getByRole("navigation", { name: "Learner steps" });
  await expect(steps.getByRole("button", { name: "2 Generate", exact: true })).toBeEnabled();
  await expect(steps).toContainText("Dataset expired. Collect new evidence.");
  await expect(page.getByRole("button", { name: "Generate suggestions", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Inspect service authority" })).toBeEnabled();
  expect(state.writes).toEqual([]);
});

test("collection tabs retain drafts and surface an active watch while importing", async ({ page }) => {
  const state = await mockLearner(page);
  await page.goto("/pcap/");
  await page.getByRole("tab", { name: "Watch live", exact: true }).click();
  const duration = page.getByLabel("Duration (seconds)", { exact: true });
  await duration.fill("120");
  await page.getByRole("button", { name: "Start watch", exact: true }).click();
  await expect(page.getByLabel("Dataset review")).toContainText("live · collecting");
  await expect(page.getByRole("navigation", { name: "Learner steps" })).toContainText("Collection must finish before generation.");
  await page.getByRole("tab", { name: "Import capture", exact: true }).click();
  await expect(page.getByText("Live watch collecting · 1 active. Open Watch live to inspect or stop collection.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Stop watch", exact: true })).not.toBeVisible();
  await page.getByRole("tab", { name: "Watch live", exact: true }).click();
  await expect(duration).toHaveValue("120");
  await expect(page.getByRole("button", { name: "Stop watch", exact: true })).toBeEnabled();
  expect(state.writes).toEqual([{ path: "/learn/watches", body: { durationSeconds: 120 } }]);
});

test("collapsed store counts still indicate removed and rejected evidence", async ({ page }) => {
  await mockLearner(page);
  await page.route("**/api/v1/learn/counters", route => route.fulfill({ json: {
    records: 24, bytes: 8192, evictedRecords: 2, evictedBytes: 100,
    expiredRecords: 3, lostBatches: 4, rejectedParents: 5, withheld: {},
  } }));
  await page.goto("/pcap/");
  const disclosure = page.locator("details").filter({ has: page.locator("summary").filter({ hasText: "Store-wide admission and withheld counts" }) });
  await expect(disclosure).toHaveJSProperty("open", false);
  for (const text of ["lost batches 4", "rejected parents 5", "evicted records 2", "expired records 3"]) {
    await expect(disclosure.locator("summary")).toContainText(text);
  }
});


for (const stopReason of ["restart", "budget", "policy_changed", "future_stop_reason", "operator", "deadline"]) {
  test(`Import capture surfaces ${stopReason} watch stop without selecting a dataset`, async ({ page }) => {
    const state = await mockLearner(page);
    const stoppedAt = new Date().toISOString();
    state.watches = [{
      id: "stopped-watch", datasetId: "capture-1", stopReason,
      startedAt: new Date(Date.now() - 60000).toISOString(),
      deadline: new Date(Date.now() + 60000).toISOString(), stoppedAt,
    }];
    await page.goto("/pcap/");
    await expect(page.getByRole("tab", { name: "Import capture", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByLabel("Dataset review", { exact: true })).toHaveCount(0);
    const notice = page.getByRole("status", { name: "Abnormally stopped watches" });
    if (["operator", "deadline"].includes(stopReason)) {
      await expect(notice).toHaveCount(0);
    } else {
      await expect(notice).toBeVisible();
      await expect(notice).toContainText(stopReason);
      const link = notice.getByRole("link", { name: "Inspect watch stopped-watch", exact: true });
      await expect(link).toHaveAttribute("href", "#watch-stopped-watch");
      await link.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByRole("tab", { name: "Watch live", exact: true })).toHaveAttribute("aria-selected", "true");
      await expect(page.locator("#watch-stopped-watch")).toBeFocused();
      await expect(page.locator("#watch-stopped-watch")).toContainText(stopReason);
      await expect(page.locator("#watch-stopped-watch")).toContainText("Dataset capture-1");
    }
    expect(state.writes).toEqual([]);
  });
}

test("service authority inspection stays available during staging without releasing mutation guards", async ({ page }) => {
  await mockLearner(page);
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  const attempts: unknown[] = [];
  await page.route("**/api/v1/learn/apply", async (route) => {
    attempts.push(route.request().postDataJSON());
    await held;
    await route.fulfill({ status: 503, json: { error: "completion unavailable" } });
  });
  try {
    await openDataset(page);
    await page.getByLabel("Select modbus-1", { exact: true }).check();
    const stage = page.getByRole("button", { name: "Stage 1 selected", exact: true });
    await stage.click();
    await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
    await expect.poll(() => attempts.length).toBe(1);
    const inspect = page.getByRole("button", { name: "Inspect service authority", exact: true });
    await expect(inspect).toBeEnabled();
    await inspect.click();
    await expect(page.getByLabel("Service authority", { exact: true })).toContainText("logical · verified");
    await expect(stage).toBeDisabled();
    await expect(page.getByRole("button", { name: "Generate suggestions", exact: true })).toBeDisabled();
    await expect(page.getByLabel("Select modbus-1", { exact: true })).toBeDisabled();
    expect(attempts).toEqual([{ requestId: expect.any(String), selections: [{ id: "modbus-1", revision: 2 }] }]);
    release();
    await expect(page.getByText("completion unavailable", { exact: true })).toBeVisible();
    await inspect.click();
    await expect(page.getByLabel("Service authority", { exact: true })).toContainText("logical · verified");
    await expect(page.getByText("completion unavailable", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry same staging request", exact: true })).toBeDisabled();
  } finally {
    release();
  }
});

test("authority errors and pagination preserve an uncertain staging receipt", async ({ page }) => {
  const state = await mockLearner(page);
  state.uncertain = true;
  let authorityFails = true;
  await page.route("**/api/v1/learn/datasets/capture-1/observations?*", async (route) => {
    if (authorityFails) {
      await route.fulfill({ status: 503, json: { error: "authority unavailable" } });
      return;
    }
    const more = !!new URL(route.request().url()).searchParams.get("cursor");
    await route.fulfill({ json: {
      items: [{
        id: more ? "second" : "first",
        service: { clientIp: more ? "192.0.2.12" : "192.0.2.11", serverIp: "192.0.2.20", serverPort: 502, transport: "tcp", protocol: "modbus", direction: "request", coordinates: "logical" },
        authority: { roleCertain: true, standardPort: true, correlation: "verified" },
        quality: { complete: true, decoded: true },
      }],
      ...(!more ? { nextCursor: "second-page" } : {}),
    } });
  });
  await openDataset(page);
  await page.getByLabel("Select modbus-1", { exact: true }).check();
  await page.getByRole("button", { name: "Stage 1 selected", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("completion unavailable", { exact: true })).toBeVisible();
  const inspect = page.getByRole("button", { name: "Inspect service authority", exact: true });
  await inspect.click();
  await expect(page.getByText("authority unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("completion unavailable", { exact: true })).toBeVisible();
  authorityFails = false;
  await inspect.click();
  const authority = page.getByLabel("Service authority", { exact: true });
  await expect(authority).toContainText("192.0.2.11");
  await expect(page.getByText("authority unavailable", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Load more observations", exact: true }).click();
  await expect(authority.locator("tbody tr")).toHaveCount(2);
  await expect(authority).toContainText("192.0.2.11");
  await expect(authority).toContainText("192.0.2.12");
  await expect(page.getByText("completion unavailable", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry same staging request", exact: true })).toBeDisabled();
  expect(state.writes).toHaveLength(1);
});
