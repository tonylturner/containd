#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Runs the protection-bind and scanning-gate kernel tests headless in a disposable golang
# container on Docker's Linux kernel: the nft steering (TestGateKernel) and
# the nft load of every golden ruleset in pkg/dp/enforce, the gate policy
# routing in pkg/dp/netcfg (TestGateRoutingKernel) and the gate manager in
# pkg/app/engine (TestGateManagerKernel). Network namespaces need SYS_ADMIN
# in addition to NET_ADMIN and NET_RAW; no host ports or shared networks are
# used. Build and module caches live in named Docker volumes, never inside
# the repository. Override KERNEL_TEST_RUN and pass package paths after --
# to select other kernel tests; other arguments go to go test.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
go_version="$(sed -n 's/^go \([0-9.]*\)$/\1/p' "$root/go.mod")"
image="containd-gate-kernel:${go_version}"
run="${KERNEL_TEST_RUN:-^TestProtectionBindKernel$|^TestGateKernel$|^TestKernelNFTLoadsGoldens$|^TestGateRoutingKernel$|^TestGateManagerKernel$}"
packages=(./pkg/dp/engine ./pkg/dp/enforce ./pkg/dp/netcfg ./pkg/app/engine)
test_args=(-v)
while (($#)); do
  if [[ "$1" == "--" ]]; then
    shift
    if (($# == 0)); then
      echo "expected package paths after --" >&2
      exit 2
    fi
    packages=("$@")
    break
  fi
  test_args+=("$1")
  shift
done
docker build -q -t "$image" - <<DOCKERFILE >/dev/null
FROM golang:${go_version}
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 python3 && rm -rf /var/lib/apt/lists/*
DOCKERFILE
# -p 1: the packages run one at a time because the netcfg and engine tests
# install the gate's policy routing in the namespace-global table 104010,
# and parallel packages would see and remove each other's objects.
docker run --rm --cpus 2 --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  --sysctl net.ipv4.conf.all.rp_filter=1 --sysctl net.ipv4.conf.default.rp_filter=1 \
  --sysctl net.bridge.bridge-nf-call-iptables=0 --sysctl net.bridge.bridge-nf-call-ip6tables=0 \
  -e CONTAIND_NETNS_KERNEL_TEST=1 -e GOFLAGS=-mod=mod \
  -v "$root:/src" -v containd-gate-kernel-gocache:/root/.cache/go-build -v containd-gate-kernel-gomod:/go/pkg/mod \
  -w /src "$image" \
  go test -p 1 -count=1 -timeout 600s \
  -run "$run" "${test_args[@]}" "${packages[@]}"
