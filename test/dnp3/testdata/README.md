# DNP3 reference captures

Fixtures use the independent opendnp3 master/outstation recipes in `../capture/`.
They are Apache-2.0 wire fixtures; the generator's upstream notices are retained
separately. The machine-readable manifest records actual generator inputs,
image/package identities, topology, capture side and tshark 4.6.7 preferences.
SHA256SUMS authenticates every referenced pcap, normalized oracle, expectation
file and auxiliary asset. The manifest does not hash itself.

Original traffic and named byte-offset CRC mutations are separate scenarios.
Oracle rows are independent observations, not containd output or policy verdicts.
Each TCP record retains its complete original payload even when multiple link
frames or application objects are observed. Qualifiers and individual indices
are normalized from PDML subtrees. CROBs retain encoded controls and timings.

The fixture scope includes startup/integrity, class/range reads, unsolicited
traffic, select/operate and direct operate, error IIN, link-only exchanges and
multi-link/multi-application-fragment responses. It is not IEEE certification,
vendor-device interoperability proof, or atomic inline prevention evidence.
See `../capture/README.md` for the generation and coverage gates.
