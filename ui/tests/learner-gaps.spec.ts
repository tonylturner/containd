import { expect, test } from "@playwright/test";
import { mockLearner, openDataset } from "./fixtures/learner";

for (const gap of ["watch_collection_loss", "budget_exceeded"]) {
  test(`connections outside localized ${gap} can generate certified suggestions`, async ({
    page,
  }) => {
    const state = await mockLearner(page);
    state.datasets[0].source = "live";
    state.datasets[0].gaps = [gap];
    state.suggestions[0].content.limits = [
      ...(state.suggestions[0].content.limits ?? []),
      `Collection limitation: ${gap}`,
    ];
    await openDataset(page);

    const review = page.getByLabel("Dataset review");
    await expect(review.getByRole("status")).toContainText(
      `Collection limitations: ${gap}`,
    );
    await expect(review.getByRole("status")).toContainText(
      "Connections that loss could have touched are excluded",
    );
    const generate = review.getByRole("button", {
      name: "Generate suggestions",
      exact: true,
    });
    await expect(generate).toBeEnabled();
    const generated = page.waitForResponse(
      (response) =>
        new URL(response.url()).pathname === "/api/v1/learn/generate" &&
        response.request().method() === "POST",
    );
    await generate.click();
    await generated;
    await expect(
      review.getByRole("status").filter({ hasText: "Generation complete:" }),
    ).toContainText("2 certified suggestion(s). Nothing selected.");
    expect(state.writes).toEqual([
      { path: "/learn/generate", body: { datasetId: state.datasets[0].id } },
    ]);
    const modbus = page.getByRole("article", {
      name: "Suggestion modbus-1",
      exact: true,
    });
    await expect(modbus.getByLabel("Certification warnings")).toContainText(
      `Collection limitation: ${gap}`,
    );
    const select = modbus.getByLabel("Select modbus-1", { exact: true });
    await expect(select).toBeEnabled();
    await expect(select).not.toBeChecked();
    await expect(
      review.getByRole("button", { name: "Stage 0 selected", exact: true }),
    ).toBeDisabled();
  });
}

test("unlocalized loss yields no suggestions and explains withheld parents", async ({
  page,
}) => {
  const state = await mockLearner(page);
  state.datasets[0].gaps = ["legacy_collection_loss"];
  await page.route("**/api/v1/learn/generate", async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      datasetId: state.datasets[0].id,
    });
    state.suggestions = [];
    await route.fulfill({
      json: { suggestions: [], withheld: { collection_loss: 24 } },
    });
  });
  await openDataset(page);
  const review = page.getByLabel("Dataset review");
  await expect(review.getByRole("status")).toContainText(
    "excludes the entire dataset",
  );
  const generated = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === "/api/v1/learn/generate" &&
      response.request().method() === "POST",
  );
  await review.getByRole("button", { name: "Generate suggestions", exact: true }).click();
  await generated;
  await expect(review.getByRole("status").filter({ hasText: "Generation complete:" }))
    .toContainText("0 certified suggestion(s). Nothing selected.");
  await expect(review.getByText("collection_loss: 24", { exact: false }))
    .toContainText("Connection excluded: collection loss may hide observations");
  await expect(page.getByRole("article", { name: "Suggestion modbus-1", exact: true }))
    .toHaveCount(0);
  await expect(review.getByRole("button", { name: "Stage 0 selected", exact: true }))
    .toBeDisabled();
});

test("gaps do not bypass collection state, expiry or backend certification", async ({
  page,
}) => {
  const state = await mockLearner(page);
  state.datasets[0].gaps = ["watch_restart"];
  state.datasets[0].state = "collecting";
  await openDataset(page);
  const generate = page.getByRole("button", {
    name: "Generate suggestions",
    exact: true,
  });
  await expect(generate).toBeDisabled();

  state.datasets[0].state = "sealed";
  state.datasets[0].expiresAt = new Date(Date.now() - 1000).toISOString();
  await openDataset(page);
  await expect(generate).toBeDisabled();

  state.datasets[0].expiresAt = new Date(Date.now() + 86400000).toISOString();
  await page.route("**/api/v1/learn/generate", async (route) => {
    // Consume the body before exposing the request as handled.
    expect(route.request().postDataJSON()).toEqual({
      datasetId: state.datasets[0].id,
    });
    await route.fulfill({
      status: 409,
      json: { error: "no complete parents eligible for certification" },
    });
  });
  await openDataset(page);
  await expect(generate).toBeEnabled();
  await generate.click();
  await expect(
    page.getByLabel("Dataset review").getByRole("alert"),
  ).toContainText("no complete parents eligible for certification");
  expect(state.writes).toEqual([]);
});
