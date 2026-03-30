#!/bin/bash
# Run pktgate functional tests.
# Must be run as root (XDP requires CAP_BPF + CAP_NET_ADMIN).
#
# Usage:
#   sudo bash functional_tests/run.sh              # all tests
#   sudo bash functional_tests/run.sh test_l2_mac.py  # single file
#   sudo bash functional_tests/run.sh -k "tcp_80"  # keyword filter

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: must be run as root (XDP/BPF requires privileges)"
    echo "Usage: sudo bash $0 [pytest args...]"
    exit 1
fi

# Check binary
if [[ ! -x "$PROJECT_DIR/build/pktgate_ctl" ]]; then
    echo "Error: pktgate_ctl not found at $PROJECT_DIR/build/pktgate_ctl"
    echo "Build first: cd $PROJECT_DIR && cmake -B build && cmake --build build"
    exit 1
fi

# Cleanup on exit (namespaces)
cleanup() {
    ip netns del ns_ft_filter 2>/dev/null || true
    ip netns del ns_ft_client 2>/dev/null || true
    # Kill any orphan pktgate processes from tests
    pkill -f "pktgate_ctl.*pktgate_ft_" 2>/dev/null || true
}
trap cleanup EXIT

# Ensure pytest/scapy are importable under sudo
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}/home/user/.local/lib/python3.11/site-packages"

cd "$SCRIPT_DIR"
exec python3 -m pytest "$@"
