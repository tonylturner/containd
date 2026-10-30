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
  await expect(modbus).toContainText("24/24 passed");
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

test("409 is atomic: server reason, no partial success, refreshed revisions and empty selection", async ({
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
    page.getByRole("button", { name: "Stage 0 selected", exact: true }),
  ).toBeDisabled();
  await expect(page.getByText(pending, { exact: true })).toHaveCount(0);
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
    page.getByText("Certified evidence (frozen)", { exact: true }).first(),
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
            datasets.getByRole("term").filter({ hasText: new RegExp(`^${label}$`) }),
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
        });
      }
    });
  }
