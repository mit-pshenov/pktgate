#!/bin/bash
# Set up veth pair with network namespaces for live XDP pktgate testing.
#
# Topology:
#   ns_pktgate:  veth-pktgate  10.0.0.1/24  (XDP pktgate attached here)
#   ns_client:  veth-client  10.0.0.2/24  (traffic source)
#
# Usage: sudo bash demo/setup_veth.sh

set -e

echo "=== Creating network namespaces ==="
ip netns add ns_pktgate 2>/dev/null || true
ip netns add ns_client 2>/dev/null || true

echo "=== Creating veth pair ==="
ip link add veth-pktgate type veth peer name veth-client 2>/dev/null || true

echo "=== Moving interfaces to namespaces ==="
ip link set veth-pktgate netns ns_pktgate
ip link set veth-client netns ns_client

echo "=== Configuring ns_pktgate ==="
ip netns exec ns_pktgate ip addr add 10.0.0.1/24 dev veth-pktgate
ip netns exec ns_pktgate ip link set veth-pktgate up
ip netns exec ns_pktgate ip link set lo up

echo "=== Configuring ns_client ==="
ip netns exec ns_client ip addr add 10.0.0.2/24 dev veth-client
ip netns exec ns_client ip link set veth-client up
ip netns exec ns_client ip link set lo up

echo "=== Connectivity test ==="
ip netns exec ns_client ping -c 1 -W 1 10.0.0.1 && echo "Ping OK" || echo "Ping failed (expected before filter)"

echo ""
echo "=== Interface info ==="
echo "--- veth-pktgate (ns_pktgate) ---"
ip netns exec ns_pktgate ip link show veth-pktgate
ip netns exec ns_pktgate ip addr show veth-pktgate
echo ""
echo "--- veth-client (ns_client) ---"
ip netns exec ns_client ip link show veth-client
ip netns exec ns_client ip addr show veth-client

echo ""
echo "=== Done. MAC addresses above needed for config. ==="
