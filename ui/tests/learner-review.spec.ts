import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { mockLearner, openDataset, suggestion } from "./fixtures/learner";

const pending = "Uncommitted changes — not active until you commit.";

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
      "iec104_value: 3 — IEC command withheld: value not expressible",
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
    modbus.getByText("Evidence digest: evidence-sha", { exact: true }),
  ).not.toBeVisible();
  await evidence.locator("summary").click();
  await expect(
    modbus.getByText("Evidence digest: evidence-sha", { exact: true }),
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
      "I verified the wire addresses and service against policy/NAT coordinates.",
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
  ).toContainText("Revision 3");
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
      .filter({ hasText: "Certified evidence (frozen)" })
      .first(),
  ).toBeVisible();
  for (const name of [
    /Analyze/,
    /Generate/,
    /Start watch/,
    /Stop watch/,
    /Review and approve/,
    /Reject/,
    /Stage \d/,
    /Preview live/,
  ])
    await expect(page.getByRole("button", { name })).toHaveCount(0);
  await expect(page.getByRole("checkbox")).toHaveCount(0);
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
