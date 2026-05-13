"""
Rate-limit functional tests.

Tests the token bucket rate-limiter by sending bursts
and verifying partial drops.
"""

import copy
import threading
import time

import pytest
from scapy.all import Ether, IP, TCP, Raw

from conftest import (
    send_and_check, send_burst, capture_count,
    PktgateProcess, CLIENT_IP4, FILTER_IP4,
    NS_CLIENT, NS_FILTER, VETH_CLIENT, VETH_FILTER,
)

pytestmark = pytest.mark.slow


def _make_rate_limit_config(veth_pair, bandwidth="1Mbps"):
    """Config with TCP/8888 rate-limited."""
    client_mac, _ = veth_pair
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "objects": {
            "mac_groups": {"allowed_macs": [client_mac]},
            "port_groups": {"rl_port": [8888]},
        },
        "pipeline": {
            "layer_2": [{
                "rule_id": 10,
                "match": {"src_mac": "object:allowed_macs"},
                "action": "allow",
                "next_layer": "layer_4",
            }],
            "layer_4": [{
                "rule_id": 1000,
                "match": {"protocol": "TCP", "dst_port": "object:rl_port"},
                "action": "rate-limit",
                "action_params": {"bandwidth": bandwidth},
            }],
        },
        "default_behavior": "drop",
    }


class TestRateLimit:
    """Rate-limit via token bucket."""

    def test_first_packet_passes(self, veth_pair):
        """First packet to a rate-limited port should always pass (token init)."""
        gate = PktgateProcess()
        try:
            gate.start(_make_rate_limit_config(veth_pair))
            client_mac, filter_mac = veth_pair
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=8888)
            )
            assert send_and_check(pkt, "tcp port 8888", expect_pass=True, count=1)
        finally:
            gate.stop()

    def test_burst_partial_drop(self, veth_pair):
        """Send 200-pkt burst at 1Mbps limit → some should be dropped."""
        gate = PktgateProcess()
        try:
            gate.start(_make_rate_limit_config(veth_pair, bandwidth="100Kbps"))
            client_mac, filter_mac = veth_pair
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=8888)
                / Raw(b"X" * 100)  # ~154 byte frame
            )

            # Start capture in background
            captured = [0]

            def _cap():
                captured[0] = capture_count("tcp port 8888", timeout=5)

            cap_t = threading.Thread(target=_cap, daemon=True)
            cap_t.start()
            time.sleep(0.5)

            # Send burst
            send_burst(pkt, count=200)

            cap_t.join(timeout=8)

            # At 100Kbps with ~154 byte packets: ~81 pkt/s max
            # A burst of 200 in <1s should see significant drops
            assert captured[0] > 0, "At least some packets should pass"
            assert captured[0] < 200, f"Expected partial drop, but all {captured[0]} passed"

        finally:
            gate.stop()

    @pytest.mark.xfail(
        reason="emergent finding 2026-05-13: post-reload bandwidth=1Mbps "
        "passes 0/500 packets (low=41 before reload, high=0 after). "
        "Either inotify-driven reload races with XDP attach state, or "
        "rate_state_map carries stale per-CPU buckets from generation 0 "
        "into generation 1. See ARCHITECTURE.md §9a Known limitations "
        "entry to be added; tracker: testing-roadmap #7.",
        strict=False,
    )
    def test_reload_changes_effective_rate(self, veth_pair):
        """Reloading the config from 100Kbps to 1Mbps must visibly change
        effective throughput. Guards P1#7-class regressions where
        rate_state_map state leaks across generations and a rule_id
        reshuffle silently passes everything (entry-exhaustion path).
        """
        gate = PktgateProcess()
        try:
            gate.start(_make_rate_limit_config(veth_pair, bandwidth="100Kbps"))
            client_mac, filter_mac = veth_pair
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=8888)
                / Raw(b"X" * 100)
            )

            def _burst_and_count(seconds=3):
                captured = [0]

                def _cap():
                    captured[0] = capture_count("tcp port 8888", timeout=seconds)

                cap_t = threading.Thread(target=_cap, daemon=True)
                cap_t.start()
                time.sleep(0.5)
                send_burst(pkt, count=500)
                cap_t.join(timeout=seconds + 3)
                return captured[0]

            low_passed = _burst_and_count()

            # Reload to 10× the bandwidth. New generation should reset the
            # token bucket; effective rate must follow.
            gate.reload_config(_make_rate_limit_config(veth_pair, bandwidth="1Mbps"))

            high_passed = _burst_and_count()

            assert low_passed > 0, "low-rate phase must let some through"
            assert high_passed > low_passed * 3, (
                f"reload from 100Kbps to 1Mbps did not raise effective rate: "
                f"low={low_passed}, high={high_passed} (need high > 3×low)"
            )
        finally:
            gate.stop()
