# RangerDanger firewall policies (pinned copies)

These byte-for-byte copies of shipped RangerDanger US and EU policies test
compatibility with strict ICS decoding, validation, config round trips and
ordered-policy upgrades. They are used only as test data.

| File | Source | SHA-256 |
|---|---|---|
| `substation-weak.json` | `rangerdanger@cee4105:lab-definitions/firewall/substation-weak.json` | `ef215ade8d0d65716007b3acda04a35cd399929a3daef19ca72954e24f6d1a9a` |
| `substation-improved.json` | `rangerdanger@cee4105:lab-definitions/firewall/substation-improved.json` | `c8f967e4c6cec77e4f24d2fd602e4f63daafff3bf0121871ef8a9546a2d9edb4` |
| `eu-weak.json` | `rangerdanger@2ef00eebdf82a7b742d182bd803da12f45aa31bc:lab-definitions/packages/eu-iec104-substation/firewall/weak.json` | `e2ff4efbb4dcedb5db88a4186876ba26bb036eb35b6b7782fa15c72e1602b9cd` |
| `eu-improved.json` | `rangerdanger@2ef00eebdf82a7b742d182bd803da12f45aa31bc:lab-definitions/packages/eu-iec104-substation/firewall/improved.json` | `b2a1e162d82cc077f2637131ac4930bf96622914caf66e93dac5ef4361a3d3bf` |

Refresh the copies only as an intentional compatibility-fixture update when
the upstream policies change, updating the pinned source revision and hashes
together. Do not hand-edit the fixture policies or modify an upstream checkout
as part of refreshing these copies.
