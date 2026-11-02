# Recorded IT protocol captures

The capture lab runs Debian clients and servers on a private Docker bridge. A
tcpdump sidecar shares each server's network namespace and records its `eth0`
traffic. The bridge uses the RFC 5737 `198.51.100.0/24` documentation prefix,
publishes no host ports, and is removed after the run. The capture set uses
only `example.test`, reserved IPv4/IPv6 addresses, and disposable credentials.

`Dockerfile` pins the Debian 12 multi-architecture image index by digest and
uses the Debian snapshot from 2026-10-31 with exact package versions. The
resulting image ID, package inventory, capture-side topology, frame counts and
per-capture description are written into `test/it/testdata/manifest.json`.
Installed source-package copyright notices for the clients, servers and
tcpdump are retained in `LICENSES/`.

To regenerate the committed captures, run from the repository root with Docker
and Python 3 available:

```sh
bash test/it/capture/capture.sh "$PWD/test/it/testdata"
(cd test/it/testdata && sha256sum -c SHA256SUMS)
go test -race ./pkg/dp/internal/corpus/ -run TestITRecordedCaptureDecoders
```

The script builds and removes its uniquely named `o1cap-*` image, network and
containers. It never publishes ports or prunes Docker resources. Pass another
output directory to retain a fresh run beside the committed capture set.
