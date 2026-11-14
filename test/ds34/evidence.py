#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read Ethernet/IPv4 TCP pcaps, preserving sequence numbers and retransmits."""
import json
import re
import struct


def packets(path):
    raw = path.read_bytes()
    assert len(raw) > 24, f"header-only or missing capture: {path}"
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}[raw[:4]]
    assert struct.unpack_from(endian + "I", raw, 20)[0] == 1, "Ethernet capture required"
    off, count = 24, 0
    while off < len(raw):
        sec, usec, size, _ = struct.unpack_from(endian + "IIII", raw, off)
        data = raw[off + 16:off + 16 + size]
        assert len(data) == size, "truncated capture record"
        off += 16 + size
        count += 1
        if len(data) < 54 or data[12:14] != b"\x08\x00" or data[23] != 6:
            continue
        ip = data[14:]
        tcp = ip[(ip[0] & 15) * 4:struct.unpack_from("!H", ip, 2)[0]]
        src, dst, seq = struct.unpack_from("!HHI", tcp)
        head = (tcp[12] >> 4) * 4
        yield {"time": sec + usec / 1e6, "src": src, "dst": dst, "seq": seq,
               "flags": tcp[13], "window": struct.unpack_from("!H", tcp, 14)[0], "payload": tcp[head:].hex()}
    assert count > 0, f"empty capture: {path}"


def field_for(receiver):
    return "dst" if receiver == "master" else "src"


def request_rejected(case):
    return (case["fate"] == "denied-request" or case.get("kind") == "timeout" or
            case.get("kind") == "session" and not case.get("explicit", True))


def denied_delivery(case, receiver):
    if receiver == "master":
        return case["expect"] == "deny"
    return case["fate"] == "missing" or request_rejected(case)


def check_pcaps(out, cases):
    failures, summary = [], {}
    for receiver in ("master", "outstation"):
        rows = list(packets(out / (receiver + ".pcap")))
        if receiver == "outstation":
            rows += list(packets(out / "upstream.pcap"))
        summary[receiver] = rows
        for case in cases:
            port = case["port"]
            matched = [p for p in rows if (p["dst"] if receiver == "master" else p["src"]) == port]
            payloads = [p for p in matched if p["payload"]]
            # A missing-request case legitimately carries no request bytes;
            # SYN/SYN-ACK must still prove that this receiver was captured.
            if not matched:
                failures.append(f"case {case['id']}: no {receiver} packets")
            denied = denied_delivery(case, receiver)
            if denied and payloads:
                failures.append(f"case {case['id']}: denied {receiver} payload: {payloads}")
            if not denied and not payloads:
                failures.append(f"case {case['id']}: missing positive {receiver} payload")
            if case.get("kind") == "timeout" and receiver == "master":
                writes = [p for p in rows if p["src"] == port and p["payload"]]
                resets = [p for p in rows if p["dst"] == port and p["flags"] & 4]
                if not writes or not resets or not 1.0 <= resets[0]["time"] - writes[0]["time"] <= 1.3:
                    failures.append(f"case {case['id']}: reset not within hold deadline plus sweep allowance")
            if case.get("independent"):
                collateral = [p for p in rows if p[field_for(receiver)] == port + 1000 and p["payload"]]
                if collateral:
                    failures.append(f"case {case['id']}: held independent flow leaked {receiver} bytes")
            # Store each distinct byte by TCP sequence, not recv() counts.
            stream = {}
            for p in payloads:
                for i, b in enumerate(bytes.fromhex(p["payload"])):
                    key = (p["seq"] + i) & 0xffffffff
                    if key in stream and stream[key] != b:
                        failures.append(f"case {case['id']}: inconsistent retransmitted byte {key}")
                    stream[key] = b
            (out / f"case-{case['id']}-{receiver}-bytes.json").write_text(json.dumps(stream, sort_keys=True) + "\n")
            if case["expect"] == "pass" and not denied:
                logs = [json.loads(line) for line in (out / f"case-{case['id']}.log").read_text().splitlines() if line.startswith("{")]
                expected = next((row for row in logs if row.get("event") == "expected"), None)
                needle = expected["response_wire" if receiver == "master" else "request_wire"] if expected else None
                ordered = bytes(stream[key] for key in sorted(stream)).hex()
                contiguous = not stream or max(stream) - min(stream) + 1 == len(stream)
                if not needle or needle not in ordered or not contiguous:
                    failures.append(f"case {case['id']}: complete expected {receiver} unit absent in TCP sequence evidence")
            if case.get("window") and receiver == "master":
                # The client's SYN advertises its real unscaled receiver window.
                syn = [p for p in rows if p["src"] == port and p["flags"] & 2]
                if not syn or syn[0]["window"] > 1152:
                    failures.append(f"case {case['id']}: minimum-window control not established: {syn}")
    (out / "tcp-evidence.json").write_text(json.dumps(summary, indent=2) + "\n")
    return failures


def attributes(line, kind):
    match = re.search(r'nla_type=' + kind + r'}, "((?:\\x[0-9a-f]{2})+)"', line)
    return bytes.fromhex(match[1].replace("\\x", "")) if match else None


def check_verdicts(out):
    inputs, sends = [], []
    for path in out.glob("netlink.*"):
        for line in path.read_text(errors="replace").splitlines():
            if "NFNL_SUBSYS_QUEUE<<8|NFQNL_MSG_PACKET" in line and "recvmsg(" in line:
                head, payload = attributes(line, "0x1"), attributes(line, "0xa")
                if head and payload and len(payload) >= 40 and payload[9] == 6:
                    tcp = payload[(payload[0] & 15) * 4:]
                    src, dst, seq = struct.unpack_from("!HHI", tcp)
                    inputs.append({"time": float(line.split()[0]), "id": int.from_bytes(head[:4], "big"),
                                   "src": src, "dst": dst, "seq": seq,
                                   "payload": tcp[(tcp[12] >> 4) * 4:].hex()})
            if ("NFNL_SUBSYS_QUEUE<<8|NFQNL_MSG_VERDICT" in line and
                ("sendmsg(" in line or "sendto(" in line) and re.search(r"= [1-9][0-9]*$", line)):
                header = attributes(line, "0x2")
                if header and len(header) == 8:
                    verdict, packet_id = struct.unpack("!II", header)
                    sends.append({"time": float(line.split()[0]), "id": packet_id, "verdict": verdict,
                                  "file": path.name, "syscall": line})
    matched, failures = [], []
    inputs.sort(key=lambda row: row["time"])
    for verdict in sends:
        candidates = [row for row in inputs if row["id"] == verdict["id"] and row["time"] <= verdict["time"]]
        if candidates:
            matched.append({**candidates[-1], **verdict})
    cases = json.loads((out / "cases.json").read_text())
    captures = json.loads((out / "tcp-evidence.json").read_text())
    for case in cases:
        if case.get("monitor"):
            continue
        for receiver in ("master", "outstation"):
            field = "dst" if receiver == "master" else "src"
            records = [row for row in matched if row[field] == case["port"] and row["payload"]]
            denied = denied_delivery(case, receiver)
            expected_input = not (receiver == "outstation" and case["fate"] == "missing" or
                                  receiver == "master" and request_rejected(case))
            if expected_input and not records:
                failures.append(f"case {case['id']}: no correlated {receiver} payload verdict")
            if records and not any(row["verdict"] == (0 if denied else 4) for row in records):
                failures.append(f"case {case['id']}: no {'drop' if denied else 'repeat'} submission for {receiver}")
            delivered = {((p["seq"] + i) & 0xffffffff, b) for p in captures[receiver] if p[field] == case["port"]
                         for i, b in enumerate(bytes.fromhex(p["payload"]))}
            for row in records:
                if not denied and row["verdict"] == 4:
                    authorized = {((row["seq"] + i) & 0xffffffff, b) for i, b in enumerate(bytes.fromhex(row["payload"]))}
                    if not authorized <= delivered:
                        failures.append(f"case {case['id']}: repeated bytes absent at {receiver} for queue id {row['id']}")
    (out / "verdict-submissions.json").write_text(json.dumps(matched, indent=2) + "\n")
    if not matched:
        failures.append("no correlated successful NFQUEUE verdict submissions in syscall evidence")
    return failures
