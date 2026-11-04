#!/bin/sh
set -eu

# Exercise link setup in a different order after restart, preserving Compose names.
generation=0
if [ -f /data/nic-generation ]; then
  generation=$(cat /data/nic-generation)
fi
k=0
while [ "$k" -lt 8 ]; do
  i=$(((k + generation) % 8))
  case "$i" in
    0) name=wan ;;
    1) name=dmz ;;
    *) name="lan$((i - 1))" ;;
  esac
  ip link set "$name" down
  ip link set "$name" up
  k=$((k + 1))
done
ip route flush default
exec /usr/bin/containd "$@"
