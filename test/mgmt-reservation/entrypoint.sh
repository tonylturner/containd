#!/bin/sh
set -eu

# Own test namespace only: deterministic NIC renumbering across process boots.
# This is deployment fixture setup, not application config migration.
generation=0
if [ -f /data/nic-generation ]; then
  generation=$(cat /data/nic-generation)
fi
i=0
while [ "$i" -lt 8 ]; do
  address="$MGMT_SMOKE_PREFIX.$i.2/24"
  device=$(ip -o -4 addr show | awk -v address="$address" '$4 == address {print $2}')
  test -n "$device"
  ip link set "$device" down
  ip link set "$device" name "c2tmp$i"
  i=$((i + 1))
done
i=0
while [ "$i" -lt 8 ]; do
  name="c2nic$(((i + generation) % 8))"
  ip link set "c2tmp$i" name "$name"
  ip link set "$name" up
  i=$((i + 1))
done
ip route flush default
exec /usr/bin/containd "$@"
