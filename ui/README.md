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
