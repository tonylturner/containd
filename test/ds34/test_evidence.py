# SPDX-License-Identifier: Apache-2.0
import pathlib
import struct
import tempfile
import unittest
from copy import deepcopy

from evidence import check_boundaries, packets


class CaptureTests(unittest.TestCase):
    def test_header_only_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "empty.pcap"
            path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"))
            with self.assertRaisesRegex(AssertionError, "header-only"):
                list(packets(path))

    def test_sequence_payload_and_window(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "tcp.pcap"
            eth = b"\x00" * 12 + b"\x08\x00"
            ip = bytearray(20)
            ip[0], ip[9] = 0x45, 6
            struct.pack_into("!H", ip, 2, 43)
            tcp = bytearray(20)
            struct.pack_into("!HHI", tcp, 0, 42000, 20000, 1234)
            tcp[12], tcp[13] = 0x50, 0x18
            struct.pack_into("!H", tcp, 14, 1152)
            frame = eth + ip + tcp + b"abc"
            path.write_bytes(bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000") +
                             struct.pack("<IIII", 1, 500000, len(frame), len(frame)) + frame)
            row, = packets(path)
            self.assertEqual((row["seq"], row["payload"], row["window"], row["time"]),
                             (1234, "616263", 1152, 1.5))


class VerdictTests(unittest.TestCase):
    def test_only_queue_submissions_are_authority(self):
        from evidence import check_verdicts
        with tempfile.TemporaryDirectory() as folder:
            out = pathlib.Path(folder)
            (out / "cases.json").write_text("[]")
            (out / "tcp-evidence.json").write_text("{}")
            # An nftables batch may contain the same octets as the message type.
            (out / "netlink.1").write_text('1.0 sendmsg(NFT_MSG_NEWRULE, "\\x01\\x03") = 32\n')
            self.assertTrue(check_verdicts(out))
            ip = bytearray(20)
            ip[0], ip[9] = 0x45, 6
            tcp = bytearray(20)
            struct.pack_into("!HHI", tcp, 0, 42000, 502, 1234)
            tcp[12] = 0x50
            payload = "".join(f"\\x{b:02x}" for b in ip + tcp + b"abc")
            received = ('2.0 recvmsg(NFNL_SUBSYS_QUEUE<<8|NFQNL_MSG_PACKET, '
                        '{nla_type=0x1}, "\\x00\\x00\\x00\\x07\\x08\\x00\\x02", '
                        f'{{nla_type=0xa}}, "{payload}") = 128\n')
            sent = ('3.0 sendmsg(NFNL_SUBSYS_QUEUE<<8|NFQNL_MSG_VERDICT, '
                    '{nla_type=0x2}, "\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x07") = 40\n')
            (out / "netlink.2").write_text(received + sent)
            self.assertEqual(check_verdicts(out), [])
            import json
            rows = json.loads((out / "verdict-submissions.json").read_text())
            self.assertEqual(len(rows), 1)
            self.assertEqual((rows[0]["src"], rows[0]["seq"], rows[0]["payload"], rows[0]["verdict"]),
                             (42000, 1234, "616263", 4))


class BoundaryTests(unittest.TestCase):
    def fixtures(self, direction):
        name = f"outside envelope: {direction}"
        case = {"id": 8, "port": 42008, "name": name, "protocol": "dnp3", "host": "192.0.2.1",
                "fate": "allowed", "expect": "reset", "boundary": direction, "step": 1}
        control = {**case, "id": 28, "port": 42028, "name": "monitor control", "expect": "pass",
                   "boundary": None, "monitor": True, "control_for": name}
        request = {"time": 10.0, "src": 42008, "dst": 20000, "flags": 24, "payload": "01"}
        response = {**request, "src": 20000, "dst": 42008}
        master_reset = {**response, "time": 11.05, "flags": 4, "payload": ""}
        outstation_reset = {**request, "time": 11.06, "flags": 4, "payload": ""}
        captures = {"master": [master_reset], "outstation": [outstation_reset]}
        captures["master" if direction == "request" else "outstation"].append(
            request if direction == "request" else response)
        return [case, control], captures

    def check(self, cases, captures):
        with tempfile.TemporaryDirectory() as folder:
            return check_boundaries(pathlib.Path(folder), cases, captures)

    def test_request_and_response_boundaries(self):
        for direction in ("request", "response"):
            with self.subTest(direction=direction):
                self.assertEqual(self.check(*self.fixtures(direction)), [])

    def test_each_incoming_reset_is_required(self):
        for side in ("master", "outstation"):
            with self.subTest(side=side):
                cases, captures = self.fixtures("request")
                captures[side] = [row for row in captures[side] if not row["flags"] & 4]
                self.assertTrue(any("missing incoming reset" in failure for failure in self.check(cases, captures)))

    def test_early_and_late_resets_fail(self):
        for elapsed in (0.99, 1.31):
            with self.subTest(elapsed=elapsed):
                cases, captures = self.fixtures("response")
                captures["master"][0]["time"] = 10.0 + elapsed
                self.assertTrue(any("outside hold+sweep+transit" in failure for failure in self.check(cases, captures)))

    def test_receiver_bytes_fail(self):
        for direction in ("request", "response"):
            with self.subTest(direction=direction):
                cases, captures = self.fixtures(direction)
                sender, receiver = (("master", "outstation") if direction == "request" else ("outstation", "master"))
                captures[receiver].append(deepcopy(captures[sender][-1]))
                self.assertTrue(any("leaked" in failure for failure in self.check(cases, captures)))

    def test_control_must_exist_and_preserve_profile(self):
        cases, captures = self.fixtures("response")
        self.assertTrue(any("exactly one" in failure for failure in self.check(cases[:1], captures)))
        cases[1]["step"] = 3
        self.assertTrue(any("does not preserve" in failure for failure in self.check(cases, captures)))


if __name__ == "__main__":
    unittest.main()
