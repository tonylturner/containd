# containd UI

The management UI uses Next.js App Router, React and Tailwind CSS, with pages
in `app/`, shared components in `components/`, and domain API clients in
`lib/`. From this directory, run `npm ci` then `npm run dev` for development,
or `npm run build` for the static export in `out/`. The management server
uses the first existing directory in this order: `CONTAIND_UI_DIR`, `ui/out`,
`ui/public`, `/var/lib/ngfw/ui`; the Docker image installs the export in the
last location. See [Contributing](../CONTRIBUTING.md) for prerequisites and
[Testing and Coverage](../docs/mkdocs/testing.md) for Playwright and the
MkDocs prebuild requirements.

## Runtime protection

The shell reports runtime protection independently of candidate changes. A
successful commit saves configuration; it does not certify that inspection is
ready. The protection notice describes affected traffic: fail-closed drops,
traffic not inspected by containd, or unavailable rule-hit logging.
Administrators can retry when the engine reports the observation retryable.
A changed observation or a refused retry is refreshed, not retried automatically.

One shared store polls `/api/v1/dataplane/protection` every two seconds while
protection is pending and for ten seconds after a commit or retry; otherwise
it polls every thirty seconds. Failed reads replace the observation with
unknown, rather than retaining an earlier healthy result. Component details
always come from one boot/apply observation, never the installed-ruleset view.
The topology chip and firewall/ICS indicators retain health's enforcement state
and show protection information when that state is not enforcing.
