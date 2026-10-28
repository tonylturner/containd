#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: export-oracle.sh OUTPUT_DIRECTORY}"
python3 "$here/export.py" --transport tcp "$out/explicit.pcap" "$out/connected.pcap" \
    "$out/io.pcap" "$out/msp.pcap" "$out/msp32.pcap" "$out/msp-error.pcap"
python3 "$here/export.py" --transport udp "$out/native-io.pcap" "$out/udp-short-mutation.pcap"
