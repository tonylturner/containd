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
i=0
for subnet in 10.10.10 10.20.20 10.30.30 10.40.40 10.99.99 10.60.60 10.70.70 10.80.80; do
  [ "$i" -lt "$NIC_COUNT" ] || break
  device="eth$(((i + generation) % NIC_COUNT))"
  ip link add "$device" type veth peer name "port$i"
  ip link set "port$i" netns switch
  ip -n switch link set "port$i" up
  if [ "$i" = 4 ]; then ip -n switch link set "port$i" master mgmtbr; fi
  ip addr add "$subnet.2/24" dev "$device"
  ip link set "$device" up
  i=$((i + 1))
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
