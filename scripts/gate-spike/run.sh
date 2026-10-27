#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs the scanning-gate kernel tests (pkg/dp/enforce/gate_kernel_linux_test.go
# and the nft load of every golden ruleset) headless in a disposable golang
# container on Docker's Linux kernel. Network namespaces need SYS_ADMIN in
# addition to NET_ADMIN and NET_RAW; no host ports or shared networks are
# used. Build and module caches live in named Docker volumes, never inside
# the repository.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
go_version="$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$root/go.mod")"
image="containd-gate-spike:${go_version}"
docker build -q -t "$image" - <<DOCKERFILE >/dev/null
FROM golang:${go_version}
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 python3 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.default.rp_filter=1 \
  --sysctl net.bridge.bridge-nf-call-iptables=0 --sysctl net.bridge.bridge-nf-call-ip6tables=0 \
  -e CONTAIND_NETNS_KERNEL_TEST=1 -e GOFLAGS=-mod=mod \
  -v "$root:/src" -v containd-gate-spike-gocache:/root/.cache/go-build -v containd-gate-spike-gomod:/go/pkg/mod \
  -w /src "$image" \
  go test -count=1 -timeout 300s -run '^TestGateKernel$|^TestKernelNFTLoadsGoldens$' -v ./pkg/dp/enforce "$@"
