import { staticAssetURL } from "./api-core";

/** Resolve an internal destination under the UI's runtime mount, exactly once. */
export function uiNavigationPath(path: string, pathname: string): string {
  const internal = path.startsWith("/") && !path.startsWith("//") && !path.includes("\\") ? path : "/";
  const parsed = new URL(internal, "https://ui.invalid");
  const base = staticAssetURL("/", pathname).slice(0, -1);
  const route = base && (parsed.pathname === base || parsed.pathname.startsWith(`${base}/`))
    ? parsed.pathname.slice(base.length) || "/" : parsed.pathname;
  return `${staticAssetURL(route, pathname)}${parsed.search}${parsed.hash}`;
}

/** Next's router knows the origin-root routes, not a reverse proxy's mount. */
export function navigateToUI(router: { push: (href: string) => void }, path: string) {
  const pathname = window.location.pathname;
  const destination = uiNavigationPath(path, pathname);
  if (staticAssetURL("/", pathname) === "/") {
    router.push(destination);
  } else {
    // A static export cannot change Next's build-time basePath at runtime.
    // Reload the same-origin mounted URL so its proxy serves the right route.
    window.location.assign(new URL(destination, window.location.origin).href);
  }
}
