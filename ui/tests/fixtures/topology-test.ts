import { expect, test as base } from "@playwright/test";

export { expect };

export const test = base.extend({
  page: async ({ page }, runWithPage) => {
    const warnings: string[] = [];
    page.on("console", (message) => {
      if (message.text().includes("reactflow.dev/error#002")) warnings.push(message.text());
    });
    await runWithPage(page);
    expect(warnings, "ReactFlow node/edge types must remain stable").toEqual([]);
  },
});
