# Capture-generator software notices

`capture.sh` pins its Debian 12 base image by digest and installs packages
from the Debian snapshot dated 2026-10-31. The generated `LICENSES/*.txt`
notices are copied from the source-package copyright files installed in that
image. They cover the server/client programs and tcpdump used to create the
recordings. The fixture uses reserved example addresses and names; the lab
account gets a random password for each run.

Run `test/it/capture/capture.sh` to refresh the notices from the pinned image.
The notices are Debian copyright metadata with upstream license texts and
attributions, not generated or modified project licenses.
