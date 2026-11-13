# SPDX-License-Identifier: Apache-2.0
import copy
import ipaddress
import struct
import unittest

from harness import config_for, redact
from results import (choose_subnets, delta, network_stats, pcap_summary, percentile,
                     project_name, protocol_stats, queue_delta, queue_stats,
                     summarize, tables, verify_smoke)
from runtime import Failure, cgroup_sample


class Measurements(unittest.TestCase):
    def test_name_fence(self):
        for bad in ("deploy", "rangerdanger-x", "a1-x", "containd-perf-", "../containd-perf-x", "containd-perf-X"):
            with self.assertRaises(ValueError):
                project_name(bad)
        self.assertEqual(project_name("containd-perf-test-123"), "containd-perf-test-123")

    def test_subnet_collision(self):
        a, b = choose_subnets(["10.192.0.0/16", "172.16.0.0/12"], 0)
        self.assertFalse(a.overlaps(b))
        self.assertFalse(a.overlaps(ipaddress.ip_network("10.192.0.0/16")))
        self.assertEqual((a, b), tuple(choose_subnets(["10.192.0.0/16", "172.16.0.0/12"], 0)))

    def test_matched_policy(self):
        base = dict(schema_version="current", system={})
        for protocol in ("modbus", "dnp3", "iec104"):
            off = config_for(base, protocol, "monitor", False, "10.1.0.3", "10.2.0.3")
            on = config_for(base, protocol, "monitor", True, "10.1.0.3", "10.2.0.3")
            self.assertFalse(off["dataplane"]["dpiEnabled"])
            off["dataplane"]["dpiEnabled"] = True
            self.assertEqual(off, on)
            self.assertEqual(len(on["firewall"]["rules"]), 2)
            self.assertFalse(on["firewall"]["nat"]["enabled"])
            enforce = config_for(base, protocol, "enforce", True, "10.1.0.3", "10.2.0.3")
            self.assertEqual(len(enforce["firewall"]["rules"]), 1)
            if protocol == "iec104":
                self.assertEqual(enforce["firewall"]["rules"][0]["ics"],
                                 dict(protocol="iec104", mode="enforce", readOnly=True))
            with self.assertRaises(Failure):
                config_for(base, protocol, "enforce", False, "10.1.0.3", "10.2.0.3")

    def test_queue_and_wrap(self):
        a = queue_stats("101 777 0 2 65535 0 0 4294967294 1\n")
        b = dict(a, received=2)
        self.assertEqual(queue_delta(a, b)["received"], 4)
        with self.assertRaises(ValueError):
            queue_stats("")
        with self.assertRaises(ValueError):
            delta(dict(eventCount=2), dict(eventCount=1))

    def test_counter_units(self):
        self.assertEqual(protocol_stats([], "iec104")["eventCount"], 0)
        text = "IpInReceives 100 0.0\nIpExtInOctets 4000 0.0\nIpOutRequests 90 0.0\nIpExtOutOctets 3600 0.0\nTcpRetransSegs 2 0.0"
        self.assertEqual(network_stats(text)["IpExtInOctets"], 4000)
        with self.assertRaises(ValueError):
            network_stats("IpInReceives 2")

    def test_histogram_units(self):
        histogram = dict(count=100, buckets=[50, 50])
        self.assertEqual(percentile(histogram, .5), .001)
        self.assertAlmostEqual(percentile(histogram, .99), .00101)
        self.assertIsNone(percentile(dict(count=0), .99))

    def test_capture_rejects_empty_and_truncated(self):
        header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 128, 1)
        frame = bytearray(34)
        frame[12:14] = b"\x08\x00"
        frame[16:18] = struct.pack("!H", 40)
        data = header + struct.pack("<IIII", 0, 0, 34, 54) + frame
        self.assertEqual(pcap_summary(data)["ipv4_length_distribution"], {40: 1})
        for bad in (header, data[:-1], b"not a pcap"):
            with self.assertRaises(ValueError):
                pcap_summary(bad)

    def test_oom_is_fatal(self):
        with self.assertRaises(Failure):
            cgroup_sample('{"oom_kill":1}')

    def test_redaction(self):
        self.assertEqual(redact(dict(secret="private", nested=dict(password="private"))),
                         dict(secret="REDACTED", nested=dict(password="REDACTED")))

    def test_summary_and_smoke_label(self):
        counts = dict(success=6000, request_bytes=1200, reply_bytes=1300, errors=0, timeouts=0,
                      rtt=dict(count=6000, buckets=[6000]))
        load = dict(schema=1, sessions=1, completed_sessions=1, main=counts, probe=counts, seconds=60)
        row = dict(protocol="modbus", mode="monitor", dpi=True, sessions=1, rate=100, stage="confirm",
                   load=load, cap_hits=0, queue_delta=dict(kernel_drops=0, user_drops=0),
                   peer_network_delta=dict(IpExtInOctets=4000, IpInReceives=100),
                   resources=dict(appliance=dict(cpu_cores_peak=1, memory_peak=1024)))
        row["summary"] = summarize(row)
        self.assertAlmostEqual(row["summary"]["goodput_mbps"], 8 * 2500 / 60 / 1e6)
        self.assertIsNone(row["summary"]["rtt_ms"][2])
        self.assertTrue(row["summary"]["sustainable"])
        self.assertIn("PLUMBING ONLY", tables([row], True))
        self.assertNotIn("0.000", tables([row], False))  # incomplete repeats omitted
        counts["success"] = counts["rtt"]["count"] = counts["rtt"]["buckets"][0] = 5900
        self.assertFalse(summarize(row)["sustainable"])  # below 99% of offered: saturated
        counts["success"] = counts["rtt"]["count"] = counts["rtt"]["buckets"][0] = 6000
        counts["timeouts"] = 1
        self.assertFalse(summarize(row)["sustainable"])
        counts["timeouts"] = 0
        row["cap_hits"] = 1
        self.assertFalse(summarize(row)["sustainable"])
        load["schema"] = 2
        with self.assertRaises(ValueError):
            summarize(row)

    def test_smoke_requires_real_success_not_vacuous_decode_proof(self):
        row = dict(dpi=True, load=dict(seconds=3, sessions=1, completed_sessions=1,
                   main=dict(success=300, errors=0), probe=dict(success=30, errors=0)),
                   cap_hits=0, queue_delta=dict(kernel_drops=0, user_drops=0),
                   protocol_delta=dict(eventCount=660))
        verify_smoke(row)
        for path, value in ((("load", "seconds"), .001), (("load", "completed_sessions"), 0),
                            (("load", "main", "success"), 0), (("load", "probe", "errors"), 1),
                            (("protocol_delta", "eventCount"), 0), (("cap_hits",), 1),
                            (("queue_delta", "kernel_drops"), 1)):
            bad = copy.deepcopy(row)
            target = bad
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "smoke workload failed"):
                    verify_smoke(bad)
        row["dpi"] = False
        row["protocol_delta"]["eventCount"] = 0
        verify_smoke(row)


if __name__ == "__main__":
    unittest.main()
