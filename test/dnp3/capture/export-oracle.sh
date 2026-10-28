#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: export-oracle.sh OUTPUT_DIRECTORY}"
version="$(tshark --version)"
[[ "$version" = 'TShark (Wireshark) 4.6.7 '* ]] || { printf 'tshark 4.6.7 required; got %s\n' "$version" >&2; exit 1; }
# Explicitly pin every TCP desegmentation preference; do not inherit user prefs.
for pcap in "$out"/*.pcap; do
    name="${pcap%.pcap}"
    tshark -2 -r "$pcap" -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE \
        -o tcp.check_checksum:FALSE -o ip.defragment:TRUE -o dnp3.desegment:TRUE \
        -Y 'tcp.port == 20000 && tcp.len > 0' -T pdml > "$name.pdml"
    python3 "$here/normalize.py" "$name.pdml" "$name.expected.tsv"
done
