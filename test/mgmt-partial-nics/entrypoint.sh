#!/bin/sh
set -eu
# Entire L2 lab lives inside this --network none container. The user's RD
# networks can keep identical IPAM subnets; no host bridge or route is touched.
generation=0
if [ -f /data/nic-generation ]; then generation=$(cat /data/nic-generation); fi
for name in switch source proxy outsider; do
  if [ -e "/var/run/netns/$name" ]; then ip netns delete "$name"; fi
done
ip netns add switch
ip -n switch link add mgmtbr type bridge
ip -n switch link set mgmtbr up
# Rotate creation order, never row identity or addressing.
k=0
while [ "$k" -lt "$NIC_COUNT" ]; do
  i=$(((k + generation) % NIC_COUNT))
  case "$i" in
    0) device=wan; subnet=10.10.10 ;;
    1) device=dmz; subnet=10.20.20 ;;
    2) device=lan1; subnet=10.30.30 ;;
    3) device=lan2; subnet=10.40.40 ;;
    4) device=lan3; subnet=10.99.99 ;;
    5) device=lan4; subnet=10.60.60 ;;
    6) device=lan5; subnet=10.70.70 ;;
    7) device=lan6; subnet=10.80.80 ;;
  esac
  ip link add "$device" type veth peer name "port$i"
  ip link set "port$i" netns switch
  ip -n switch link set "port$i" up
  if [ "$i" = 4 ]; then ip -n switch link set "port$i" master mgmtbr; fi
  ip addr add "$subnet.2/24" dev "$device"
  ip link set "$device" up
  k=$((k + 1))
done
for spec in source:10 proxy:3 outsider:11; do
  name=${spec%:*}
  host=${spec#*:}
  ip netns add "$name"
  ip link add "$name-port" type veth peer name peer
  ip link set "$name-port" netns switch
  ip -n switch link set "$name-port" master mgmtbr
  ip -n switch link set "$name-port" up
  ip link set peer netns "$name"
  ip -n "$name" link set lo up
  ip -n "$name" link set peer up
  ip -n "$name" addr add "10.99.99.$host/24" dev peer
done
exec /usr/bin/containd all
