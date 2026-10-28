#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
OUT=${1:?usage: export-oracle.sh testdata-directory}
TSHARK=${TSHARK:-tshark}
version=$("$TSHARK" --version)
[[ "$version" == "TShark (Wireshark) 4.6.7 "* ]]
prefs=(-2 -o tcp.desegment_tcp_streams:TRUE -o tcp.reassemble_out_of_order:TRUE
    -o mbtcp.desegment:TRUE -o modbus.mbus_register_format:UINT16)
fields=(frame.number ip.src ip.dst tcp.srcport tcp.dstport tcp.seq_raw tcp.len tcp.payload
    mbtcp.trans_id mbtcp.prot_id mbtcp.unit_id modbus.func_code modbus.exception_code
    modbus.diagnostic_code modbus.reference_num modbus.word_cnt modbus.bit_cnt modbus.byte_cnt
    modbus.read_reference_num modbus.read_word_cnt modbus.write_reference_num modbus.write_word_cnt
    modbus.and_mask modbus.or_mask modbus.regval_uint16 modbus.data)
args=()
for field in "${fields[@]}"; do args+=(-e "$field"); done
for pcap in "$OUT/"*.pcap; do
    "$TSHARK" "${prefs[@]}" -r "$pcap" -Y 'tcp.len > 0' \
        -T fields -E header=y -E separator=/t -E occurrence=a -E aggregator=, -E quote=d \
        "${args[@]}" > "${pcap%.pcap}.expected.tsv"
    test "$(wc -l < "${pcap%.pcap}.expected.tsv")" -gt 1
    # tshark leaves empty cells unquoted even with quote=d. Re-serialize the
    # same observed cells with CSV's quote-all so trailing empty columns are
    # explicit and do not create trailing whitespace.
    python3 - "${pcap%.pcap}.expected.tsv" <<'PY'
import csv
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
with path.open(newline="") as stream:
    rows = list(csv.reader(stream, delimiter="\t"))
with path.open("w", newline="") as stream:
    csv.writer(stream, delimiter="\t", quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
PY
done
