# Data Plane Packages

The dataplane packages implement Linux AF_PACKET and NFQUEUE capture
(`capture`), packet-path coordination (`engine`), flow tracking and rule/verdict
evaluation, nftables enforcement (`enforce`), stream inspection (`dpi`),
industrial protocol decoders (`ics`), IT metadata decoders (`itdpi`), IDS
evaluation, event storage, PCAP diagnostics, and network configuration
(`netcfg`). See [Dataplane](../../docs/mkdocs/dataplane.md),
[Enforcement](../../docs/mkdocs/dataplane-enforcement.md), and
[ICS DPI](../../docs/mkdocs/ics-dpi.md) for behavior and limitations.
