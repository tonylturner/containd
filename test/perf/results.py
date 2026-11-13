# SPDX-License-Identifier: Apache-2.0
"""Pure measurement calculations; no Docker or appliance mutations."""
import collections
import ipaddress
import math
import re
import statistics
import struct


def project_name(value):
    if not re.fullmatch(r"containd-perf-[a-z0-9][a-z0-9-]{0,48}", value):
        raise ValueError("COMPOSE_PROJECT_NAME must be a unique containd-perf-<suffix>")
    return value


def choose_subnets(existing, seed):
    nets = [ipaddress.ip_network(n) for n in existing]
    # Deterministic search, reject overlaps with every network, not just /24s.
    candidates = [ipaddress.ip_network(f"10.{192 + ((seed + i) % 63)}.{(seed // 63 + i // 63) % 256}.0/28")
                  for i in range(63 * 256)]
    chosen = []
    for net in candidates:
        if not any(net.overlaps(n) for n in nets + chosen):
            chosen.append(net)
            if len(chosen) == 2:
                return chosen
    raise ValueError("no free private subnets")


def queue_stats(text, queue=101):
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 9 and int(p[0]) == queue:
            return dict(queued=int(p[2]), kernel_drops=int(p[5]),
                        user_drops=int(p[6]), received=int(p[7]))
    raise ValueError("NFQUEUE 101 is not bound")


def delta(before, after):
    result = {}
    for key, value in before.items():
        if key not in after or after[key] < value:
            raise ValueError(f"counter reset/missing: {key}")
        result[key] = after[key] - value
    return result


def queue_delta(before, after):
    # id_sequence is a 32-bit delivered-packet sequence, not queue occupancy.
    result = {k: after[k] - before[k] for k in ("kernel_drops", "user_drops")}
    if min(result.values()) < 0:
        raise ValueError("NFQUEUE generation reset")
    result["received"] = (after["received"] - before["received"]) % (2**32)
    return result


def protocol_stats(rows, protocol):
    for row in rows:
        if row["protocol"] == protocol:
            return {k: row[k] for k in ("packetCount", "byteCount", "eventCount")}
    return dict(packetCount=0, byteCount=0, eventCount=0)


def hits(snapshot):
    return sum(h["total"] for table in snapshot["tables"] for h in table["hits"])


def network_stats(text):
    # nstat -az emits absolute per-network-namespace IP and TCP counters.
    raw = {p[0]: int(p[1]) for line in text.splitlines()
           if len(p := line.split()) >= 2 and p[1].isdigit()}
    names = ("IpInReceives", "IpExtInOctets", "IpOutRequests", "IpExtOutOctets", "TcpRetransSegs")
    if not all(n in raw for n in names):
        raise ValueError("missing endpoint IP/TCP counter")
    return {n: raw[n] for n in names}


def percentile(hist, q):
    if not hist["count"]:
        return None
    rank = math.ceil(hist["count"] * q)
    seen = 0
    for i, count in enumerate(hist["buckets"]):
        seen += count
        if seen >= rank:
            return 1.01**i / 1000  # us upper bound -> ms
    raise ValueError("histogram count does not match buckets")


def pcap_summary(data):
    if len(data) <= 24:
        raise ValueError("empty/header-only path capture")
    order = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(data[:4])
    if order is None or struct.unpack_from(order + "I", data, 20)[0] != 1:
        raise ValueError("expected Ethernet microsecond pcap")
    offset, packets, sizes = 24, 0, collections.Counter()
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated pcap record")
        _, _, captured, original = struct.unpack_from(order + "IIII", data, offset)
        offset += 16
        if captured > original or offset + captured > len(data):
            raise ValueError("truncated pcap payload")
        frame = data[offset:offset + captured]
        if len(frame) >= 34 and frame[12:14] == b"\x08\x00":
            sizes[struct.unpack_from("!H", frame, 16)[0]] += 1
        packets += 1
        offset += captured
    if not packets or not sizes:
        raise ValueError("path capture has no IPv4 packets")
    return dict(packets=packets, ipv4_length_distribution=dict(sizes))


def summarize(row):
    result = row["load"]
    main = result["main"]
    seconds = result["seconds"]
    if result["schema"] != 1 or seconds <= 0 or main["rtt"]["count"] != main["success"]:
        raise ValueError("invalid load result schema/counts")
    quantiles = [percentile(main["rtt"], q) for q in (.5, .95, .99)]
    if main["success"] < 10000:
        quantiles[2] = None
    return dict(tps=main["success"] / seconds,
                goodput_mbps=8 * (main["request_bytes"] + main["reply_bytes"]) / seconds / 1e6,
                rtt_ms=quantiles, errors=main["errors"], timeouts=main["timeouts"],
                cap_hits=row["cap_hits"], sustainable=(seconds >= 60 and
                    result["completed_sessions"] == result["sessions"] and
                    not (main["errors"] + result["probe"]["errors"] + row["cap_hits"] +
                         row["queue_delta"]["kernel_drops"] + row["queue_delta"]["user_drops"])),
                forward_l3_mbps=8 * row["peer_network_delta"]["IpExtInOctets"] / seconds / 1e6,
                forward_skb_pps=row["peer_network_delta"]["IpInReceives"] / seconds)


def verify_smoke(row):
    load = row["load"]
    if (load["seconds"] < 3 or load["completed_sessions"] != load["sessions"] or
            any(load[k]["errors"] or load[k]["success"] <= 0 for k in ("main", "probe")) or
            row["cap_hits"] or row["queue_delta"]["kernel_drops"] or row["queue_delta"]["user_drops"] or
            (row["dpi"] and row["protocol_delta"]["eventCount"] <= 0)):
        raise ValueError("smoke workload failed its hold, transactions, decode or loss assertions; see row.json")


def tables(rows, smoke):
    title = "PLUMBING ONLY — NOT PUBLISHABLE" if smoke else "Docker Desktop lab measurements"
    lines = [f"# {title}", "", "NFQUEUE traversal / monitor inspection; inline enforcement uses a",
             "monitor/L4 DPI-off reference, **not the identical policy**.", "",
             "| Workload / mode / DPI / N / offered tx/s | Goodput Mbps median [range] | tx/s median [range] | RTT p50/p95/p99 ms (median) | Errors/timeouts | Cap hits | Appliance CPU cores / peak MiB | Repeats |",
             "|---|---|---|---|---|---|---|---|"]
    groups = collections.defaultdict(list)
    for row in rows:
        if row["stage"] == "confirm":
            groups[(row["protocol"], row["mode"], row["dpi"], row["sessions"], row["rate"])].append(row)
    for key, group in sorted(groups.items()):
        if not smoke and len(group) < 5:
            continue  # Partial runs never masquerade as replicated figures.
        def span(field):
            v = [r["summary"][field] for r in group]
            return f"{statistics.median(v):.3f} [{min(v):.3f}–{max(v):.3f}]"
        q = [statistics.median(v) if (v := [r["summary"]["rtt_ms"][i] for r in group
                  if r["summary"]["rtt_ms"][i] is not None]) and len(v) == len(group) else None for i in range(3)]
        rtt = "/".join("insufficient samples" if n is None else f"{n:.3f}" for n in q)
        cpu = max(r["resources"]["appliance"]["cpu_cores_peak"] for r in group)
        mem = max(r["resources"]["appliance"]["memory_peak"] for r in group) / 2**20
        lines.append(f"| {' / '.join(map(str, key))} | {span('goodput_mbps')} | {span('tps')} | {rtt} | "
                     f"{sum(r['summary']['errors'] for r in group)}/{sum(r['summary']['timeouts'] for r in group)} | "
                     f"{sum(r['cap_hits'] for r in group)} | {cpu:.2f} / {mem:.1f} | {len(group)} |")
    lines += ["", "| Workload / mode / DPI | Highest confirmed N | First failing N | Hold | Limitation |",
              "|---|---|---|---|---|"]
    for protocol, mode, dpi in sorted({(k[0], k[1], k[2]) for k in groups}):
        matching = [r for r in rows if (r["protocol"], r["mode"], r["dpi"]) == (protocol, mode, dpi)]
        confirmed = [k[3] for k, g in groups.items() if k[:3] == (protocol, mode, dpi) and
                     len(g) >= (1 if smoke else 5) and all(r["summary"]["sustainable"] for r in g)]
        failures = [r["sessions"] for r in matching if not r["summary"]["sustainable"] and not smoke]
        lines.append(f"| {protocol}/{mode}/{dpi} | {max(confirmed) if confirmed else 'none'} | "
                     f"{min(failures) if failures else 'not reached'} | {'plumbing only' if smoke else '60 s'} | "
                     "bounded search; not a maximum |")
    return "\n".join(lines) + "\n"
