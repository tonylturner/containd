#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Disposable, headless Linux acceptance test. No host ports or shared networks.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
arch="$(docker info --format '{{.Architecture}}')"
case "$arch" in
  aarch64|arm64) arch=arm64 ;;
  x86_64|amd64) arch=amd64 ;;
  *) echo "Unsupported Docker architecture: $arch" >&2; exit 1 ;;
esac
mkdir -p "$root/build"
GOFLAGS=-mod=mod GOOS=linux GOARCH="$arch" CGO_ENABLED=0 \
  go test -c -o "$root/build/netcfg.test" ./pkg/dp/netcfg
project="containd-netcfg-kernel-$(date +%s)-$$"
image="$project:local"
trap 'docker image rm "$image" >/dev/null' EXIT
docker build -t "$image" - <<'EOF'
FROM alpine:3.21
RUN apk add --no-cache iproute2 nftables python3 openvpn
EOF
docker run --rm --name "$project" --cap-add NET_ADMIN --cap-add SYS_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.conf.default.rp_filter=1 \
  --sysctl net.ipv4.conf.all.rp_filter=1 \
  -e CONTAIND_NETNS_KERNEL_TEST=1 -v "$root/build:/w:ro" \
  "$image" /w/netcfg.test \
  -test.run '^TestManagementKernelMatrix$' -test.v
