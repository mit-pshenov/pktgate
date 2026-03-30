#!/bin/bash
# Clean up veth pair and namespaces.
# Usage: sudo bash demo/cleanup_veth.sh

set -e

echo "=== Cleaning up ==="
ip netns del ns_pktgate 2>/dev/null && echo "Deleted ns_pktgate" || echo "ns_pktgate not found"
ip netns del ns_client 2>/dev/null && echo "Deleted ns_client" || echo "ns_client not found"
echo "Done."
