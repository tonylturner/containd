import { expect, test } from "@playwright/test";
import { navigateToUI, uiNavigationPath, uiRoutePath } from "../lib/ui-navigation";

test("route paths strip only the mount known by the runtime base-path authority", () => {
  for (const path of ["/", "/system/services/dns/", "/zones/"]) {
    expect(uiRoutePath(path)).toBe(path);
    expect(uiRoutePath(`/containd${path}`)).toBe(path);
  }
  expect(uiRoutePath("/containd", "/containd/login/")).toBe("/");
  expect(uiRoutePath("/containd-other/zones/")).toBe("/containd-other/zones/");
  expect(uiRoutePath("/zones/containd/")).toBe("/zones/containd/");
});

for (const destination of ["/login?reason=expired&next=%2Fassets%2F", "/login?reason=logout", "/forbidden", "/"]) {
  test(`navigation preserves the runtime mount for ${destination}`, () => {
    expect(uiNavigationPath(destination, "/zones/")).toBe(destination);
    expect(uiNavigationPath(destination, "/containd/zones/")).toBe(`/containd${destination}`);
  });
}

test("return destinations cannot escape the origin or duplicate the UI mount", () => {
  expect(uiNavigationPath("/containd/assets/?q=one#details", "/containd/login/")).toBe("/containd/assets/?q=one#details");
  expect(uiNavigationPath("/containd/../assets/", "/containd/login/")).toBe("/containd/assets/");
  for (const unsafe of ["//elsewhere.example", "/\\elsewhere.example", "https://elsewhere.example"]) {
    expect(uiNavigationPath(unsafe, "/containd/login/")).toBe("/containd/");
  }
});

test("root navigation uses Next; mounted navigation reloads a same-origin URL", () => {
  const previous = globalThis.window;
  const pushed: string[] = [];
  const assigned: string[] = [];
  const location = { pathname: "/zones/", origin: "https://firewall.example", assign: (url: string) => assigned.push(url) };
  Object.defineProperty(globalThis, "window", { configurable: true, value: { location } });
  try {
    const router = { push: (path: string) => { pushed.push(path); } };
    navigateToUI(router, "/login?reason=logout");
    location.pathname = "/containd/zones/";
    navigateToUI(router, "/login?reason=logout");
    expect(pushed).toEqual(["/login?reason=logout"]);
    expect(assigned).toEqual(["https://firewall.example/containd/login?reason=logout"]);
  } finally {
    Object.defineProperty(globalThis, "window", { configurable: true, value: previous });
  }
});
