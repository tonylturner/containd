#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
source_repo="${CIPDIP_SOURCE:-/Users/tturner/Documents/GitHub/cipdip}"
commit=12c7397cf8d1a4d608c82ba3f15c788308636c57
scratch="$root/build/cip-generator"
out="$root/test/cip/testdata"
mkdir -p "$scratch" "$out"
git -C "$source_repo" archive --format=tar "$commit" -o "$scratch/source.tar"
cp "$root/test/cip/capture/client.go.txt" "$scratch/client.go.txt"
docker build -t containd-corpus-cip-generator -f "$root/test/cip/capture/Dockerfile" "$scratch"
docker network create --subnet 172.30.93.0/24 containd-corpus-cip-net
docker run -d --name containd-corpus-cip-server --network containd-corpus-cip-net --ip 172.30.93.2 \
  -v "$root/test/cip/capture/server.yaml:/config.yaml:ro" \
  containd-corpus-cip-generator server --server-config /config.yaml --enable-udp-io
docker run -d --name containd-corpus-cip-capture --network container:containd-corpus-cip-server \
  --entrypoint tcpdump -v "$out:/out" containd-corpus-cip-generator \
  -i eth0 --immediate-mode -U -w /out/explicit-io.pcap 'tcp port 44818 or udp port 2222'
sleep 2
docker run --name containd-corpus-cip-client --network containd-corpus-cip-net --ip 172.30.93.3 \
  --entrypoint corpus-client containd-corpus-cip-generator 172.30.93.2 > "$out/client.log" 2>&1
docker kill --signal SIGINT containd-corpus-cip-capture
test "$(docker wait containd-corpus-cip-capture)" = 0
test "$(wc -c < "$out/explicit-io.pcap")" -gt 24
docker logs containd-corpus-cip-server > "$out/server.log" 2>&1
docker logs containd-corpus-cip-capture > "$out/capture.log" 2>&1
docker stop containd-corpus-cip-server
docker rm containd-corpus-cip-client containd-corpus-cip-server containd-corpus-cip-capture
docker network rm containd-corpus-cip-net
shasum -a 256 "$scratch/source.tar" "$root/test/cip/capture/"* > "$scratch/generator.sha256"
if grep -q '^ERROR:' "$out/server.log"; then
  cat "$out/server.log" >&2
  echo "CIPDIP logged server errors; captures are diagnostic evidence, not a clean conformance run" >&2
  exit 1
fi
