# RangerDanger US firewall policies (pinned copies)

These byte-for-byte copies of the shipped RangerDanger US policies test
compatibility with strict ICS decoding, validation and config round trips.
They are used only as test data.

| File | Source | SHA-256 |
|---|---|---|
| `substation-weak.json` | `rangerdanger@cee4105:lab-definitions/firewall/substation-weak.json` | `ef215ade8d0d65716007b3acda04a35cd399929a3daef19ca72954e24f6d1a9a` |
| `substation-improved.json` | `rangerdanger@cee4105:lab-definitions/firewall/substation-improved.json` | `c8f967e4c6cec77e4f24d2fd602e4f63daafff3bf0121871ef8a9546a2d9edb4` |

Refresh the copies only as an intentional compatibility-fixture update when
the upstream policies change, updating the pinned source revision and hashes
together. Do not hand-edit the fixture policies or modify an upstream checkout
as part of refreshing these copies.
