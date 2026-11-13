#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Schema plus mandatory CSAF tests; the service never depends on a public validator.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# Secvisogram validator service 3.0.3 (published image supports linux/amd64).
image="ghcr.io/secvisogram/csaf-validator-service@sha256:181af4187f8f68ea443821ea1a5a57ba87a89b772282642c0e63dc37579673b3"
mkdir -p "$repo_root/build/tools"
GOBIN="$repo_root/build/tools" GOFLAGS=-mod=mod \
    go install github.com/gocsaf/csaf/v3/cmd/csaf_validator@v3.7.1
container="$(docker run --platform linux/amd64 --rm -d -p 127.0.0.1::8082 "$image")"
cleanup() {
    local result=$? stop_result=0
    docker stop "$container" >/dev/null || stop_result=$?
    if (( result != 0 )); then
        exit "$result"
    fi
    exit "$stop_result"
}
trap cleanup EXIT
port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8082/tcp") 0).HostPort}}' "$container")"
export CSAF_VALIDATOR_URL="http://127.0.0.1:$port"
export CSAF_VALIDATOR_BIN="$repo_root/build/tools/csaf_validator"
ready=0
for (( attempt=0; attempt<60; attempt++ )); do
    if curl --fail --silent --max-time 2 "$CSAF_VALIDATOR_URL/health" >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if (( ready == 0 )); then
    docker logs "$container"
    echo 'CSAF validator service did not become ready' >&2
    exit 1
fi
# gocsaf appends /api/v1/validate to the base URL. "basic" runs strict schema
# and every mandatory test (6.1.8 is covered by schema); no optional test masking.
python3 "$repo_root/scripts/csaf/validate.py" "$@"
