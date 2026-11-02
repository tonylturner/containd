# IT protocol capture fixtures

These classic Ethernet/IPv4 captures record unmodified Debian client and
server programs on a private Docker bridge. `manifest.json` records the base
image digest, generated image ID, exact installed package versions, capture
side, topology, frame counts, license references and the exchange represented
by each file. Source-package notices for the software are in
`../../capture/LICENSES/`. `SHA256SUMS` covers each pcap.

| Capture | Recorded exchange |
| --- | --- |
| `dns.pcap` | A, AAAA and TXT queries for `www.example.test`; NXDOMAIN for `missing.example.test`. |
| `tls.pcap` | TLS 1.2 and 1.3 ClientHello handshakes with separate SNI names and ALPN offers. |
| `http.pcap` | HTTP/1.1 GET and POST with Host, User-Agent and JSON Content-Type headers. |
| `ssh.pcap` | SSH version exchange and key exchange followed by a disposable password-authenticated command. |
| `ntp.pcap` | An NTP client request and server response. |
| `snmp.pcap` | An SNMPv2c GET of three system objects and a short sysName walk using the throwaway `public` community. |
| `rdp.pcap` | RDP X.224 connection request/response and security negotiation. |
| `smb.pcap` | SMB2/3 negotiation, session setup, tree connect, directory listing and a small file read. |

All captures contain full TCP handshakes where applicable. Addresses are from
RFC 5737 and RFC 3849 documentation ranges; the DNS zone is `example.test`.
No real domain is queried, no host port is published, and credentials are
confined to encrypted disposable lab sessions.

Verify the fixture bytes with `(cd test/it/testdata && sha256sum -c SHA256SUMS)`.
Regenerate the lab with
`bash test/it/capture/capture.sh "$PWD/test/it/testdata"`; Docker and Python 3
must be available. Decoder results and observed coverage gaps are reported by
`go test -v -race ./pkg/dp/internal/corpus/ -run TestITRecordedCaptureDecoders`.
