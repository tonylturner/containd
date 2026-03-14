#!/usr/bin/env sh
set -eu

REPO_OWNER=${CONTAIND_REPO_OWNER:-tonylturner}
REPO_NAME=${CONTAIND_REPO_NAME:-containd}
REF=${CONTAIND_REF:-main}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." 2>/dev/null && pwd || printf '')

if [ -f "$script_dir/bootstrap-starter.sh" ]; then
    exec sh "$script_dir/bootstrap-starter.sh" "$@"
fi

if [ -f "$repo_root/scripts/bootstrap-starter.sh" ] && [ -f "$repo_root/deploy/docker-compose.yml" ]; then
    exec sh "$repo_root/scripts/bootstrap-starter.sh" "$@"
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to download bootstrap-starter.sh" >&2
    exit 1
fi

tmp_script=$(mktemp "${TMPDIR:-/tmp}/containd-bootstrap.XXXXXX")
cleanup() {
    rm -f "$tmp_script"
}
trap cleanup EXIT

curl -fsSL "https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME/$REF/scripts/bootstrap-starter.sh" -o "$tmp_script"
exec sh "$tmp_script" "$@"
