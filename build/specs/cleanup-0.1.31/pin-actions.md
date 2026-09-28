# Pin GitHub Actions to commit SHAs

Ticket 01a0da2e. Branch: fix/post-0.1.30-cleanup (worktree lane; commit on your helper branch).

## Goal
`bash scripts/semgrep-verify.sh` reports 0 findings (currently 23 `github-actions-mutable-action-tag` across .github/workflows/ci.yml and release.yml) without weakening the script's allowlist.

## Verified facts
- Mutable refs (7 `uses:` lines): ci.yml:34 golangci/golangci-lint-action@v7, ci.yml:81 docker/setup-buildx-action@v3, ci.yml:84 docker/build-push-action@v6, release.yml:55 and :72 docker/build-push-action@v6, release.yml:149 actions/upload-artifact@v4, release.yml:159 softprops/action-gh-release@v2. Semgrep also flags actions/checkout and actions/setup-go/setup-node lines (ci.yml:15,16,29,30,41,42 and release.yml:88,97,103) — check every `uses:` in both files.
- scripts/semgrep-verify.sh runs `semgrep --config auto` (local binary or `returntocorp/semgrep` via docker); docker works on this host. Running it takes about a minute.
- `gh` is authenticated. Resolve each tag to its commit with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; if the object type is `tag` (annotated), dereference via `gh api repos/<owner>/<repo>/git/tags/<sha>` to the commit SHA. Pin to the newest patch release of the SAME major currently used (e.g. v7.x for golangci-lint-action), never a newer major.

## Contract
- Every `uses:` becomes `owner/repo@<40-char sha> # vX.Y.Z` with the resolved version in the trailing comment.
- No behavior change: same majors, same inputs. Do not touch scripts/semgrep-verify.sh or any other file.

## Fence (write)
.github/workflows/ci.yml, .github/workflows/release.yml only.

## Validation
- `bash scripts/semgrep-verify.sh` exits 0 with 0 findings (paste the summary line).
- `actionlint` if installed, otherwise `python3 -c 'import yaml,sys; [yaml.safe_load(open(f)) for f in sys.argv[1:]]' .github/workflows/*.yml`.
- List each action with old tag, pinned SHA, and version in the commit body. Report anything wrong with this spec.
