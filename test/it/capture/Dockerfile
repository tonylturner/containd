# SPDX-License-Identifier: Apache-2.0
# Debian 12 multi-architecture image index, pinned 2026-10-27.
FROM debian@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261031T000000Z bookworm main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261031T000000Z bookworm-security main' \
      > /etc/apt/sources.list \
    && : > /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' 'Acquire::Check-Valid-Until false;' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      apache2=2.4.68-1~deb12u1 \
      bind9=1:9.18.49-1~deb12u3 \
      bind9-dnsutils=1:9.18.49-1~deb12u3 \
      chrony=4.3-2+deb12u3 \
      curl=7.88.1-10+deb12u15 \
      freerdp2-x11=2.11.7+dfsg1-6~deb12u1 \
      ntpsec-ntpdate=1.2.2+dfsg1-1+deb12u1 \
      openssh-server=1:9.2p1-2+deb12u10 \
      openssl=3.0.22-1~deb12u2 \
      python3=3.11.2-1+b1 \
      samba=2:4.17.12+dfsg-0+deb12u4 \
      smbclient=2:4.17.12+dfsg-0+deb12u4 \
      snmp=5.9.3+dfsg-2+deb12u1 \
      snmpd=5.9.3+dfsg-2+deb12u1 \
      sshpass=1.09-1 \
      tcpdump=4.99.3-1 \
      xrdp=0.9.21.1-1+deb12u3 \
      xauth=1:1.1.2-1 \
      xvfb=2:21.1.7-3+deb12u13 \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete

COPY entrypoint.sh /usr/local/bin/o1cap-entrypoint
RUN chmod 0755 /usr/local/bin/o1cap-entrypoint

ENTRYPOINT ["/usr/local/bin/o1cap-entrypoint"]
