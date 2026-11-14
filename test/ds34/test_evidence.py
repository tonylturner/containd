# SPDX-License-Identifier: Apache-2.0
import pathlib
import struct
import tempfile
import unittest

from evidence import packets


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


if __name__ == "__main__":
    unittest.main()
