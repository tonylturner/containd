#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
ip route del default
# Separate processes make engine-only outages observable from management.
(
  while true; do
    strace -ff -ttt -xx -s 65535 -e trace=sendmsg,sendto,recvmsg -o /results/netlink /usr/bin/containd engine || true
    sleep 1
  done
) &
exec /usr/bin/containd mgmt
