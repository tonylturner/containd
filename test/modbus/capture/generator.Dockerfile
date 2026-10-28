# SPDX-License-Identifier: Apache-2.0
# Offline bootstrap image: Debian 12, python3 3.11.2-1+b1, tcpdump 4.99.3-1,
# iproute2 6.1.0-3, pymodbus 3.11.4 (no runtime Python dependencies).
# Preserve/distribute this base with docker save/load; it is a local image,
# not a claim that Docker Hub hosts this digest.
FROM modbusspan-tools@sha256:2bbeea56d58c5192ebda1d8314637c3c9995341df21e733110405040bae77fbc
RUN /venv/bin/python -c 'import pymodbus; assert pymodbus.__version__ == "3.11.4"'
COPY endpoint.py /generator/endpoint.py
ENTRYPOINT ["/venv/bin/python", "/generator/endpoint.py"]
