import { expect, test } from "@playwright/test";

import { staticAssetURL } from "../lib/api-core";

test("static asset URLs stay under the runtime /containd base path", () => {
  const url = staticAssetURL("/icons/docker.svg", "/containd/topology/");

  expect(url).toBe("/containd/icons/docker.svg");
  expect(url).not.toMatch(/^\/icons\//);
});

test("static asset URLs remain root-relative when the UI is at the origin root", () => {
  expect(staticAssetURL("/icons/docker.svg", "/topology/")).toBe(
    "/icons/docker.svg",
  );
});
