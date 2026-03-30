"""
Generation swap tests — verify zero-loss config reload.

Tests the double-buffer atomic swap mechanism:
  - Reload under active traffic → no packet loss on allowed flows
  - Rapid reload storm → pktgate survives, final config applied
"""

import copy
import threading
import time

import pytest
from scapy.all import Ether, IP, TCP, Raw

from conftest import (
    send_and_check, send_burst, capture_count,
    PktgateProcess, CLIENT_IP4, FILTER_IP4,
    VETH_CLIENT, VETH_FILTER,
)


def _make_swap_config(veth_pair, extra_ports=None):
    """Config for gen-swap tests. TCP/80 always allowed, extra_ports optional."""
    client_mac, _ = veth_pair
    ports = [80] + (extra_ports or [])
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "objects": {
            "mac_groups": {"allowed_macs": [client_mac]},
            "port_groups": {"web": ports},
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
                "match": {"protocol": "TCP", "dst_port": "object:web"},
                "action": "allow",
            }],
        },
        "default_behavior": "drop",
    }


class TestGenSwap:
    """Generation swap correctness."""

    def test_reload_under_traffic_no_loss(self, veth_pair):
        """Send continuous TCP/80 traffic, reload mid-stream → zero loss.

        TCP/80 is allowed in both old and new configs, so the allowed flow
        must never be interrupted during generation swap.
        """
        gate = PktgateProcess()
        try:
            config_v1 = _make_swap_config(veth_pair, extra_ports=[443])
            gate.start(config_v1)
            client_mac, filter_mac = veth_pair

            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )

            n_packets = 50
            captured = [0]

            def _cap():
                captured[0] = capture_count("tcp port 80", timeout=8)

            # Start capture
            cap_t = threading.Thread(target=_cap, daemon=True)
            cap_t.start()
            time.sleep(0.5)

            # Send packets in batches, reload between them
            send_burst(pkt, count=20)

            # Reload (changes extra_ports but TCP/80 stays allowed)
            config_v2 = _make_swap_config(veth_pair, extra_ports=[8080])
            gate.reload_config(config_v2)

            send_burst(pkt, count=30)

            cap_t.join(timeout=12)

            # All 50 packets should pass — zero loss during swap
            assert captured[0] >= n_packets, (
                f"Expected {n_packets} packets, captured {captured[0]} — "
                f"possible loss during gen swap!"
            )

        finally:
            gate.stop()

    def test_rapid_reload_storm(self, veth_pair):
        """10 rapid reloads in 2 seconds → pktgate survives, final config applied."""
        gate = PktgateProcess()
        try:
            config = _make_swap_config(veth_pair)
            gate.start(config)
            client_mac, filter_mac = veth_pair

            # Rapid fire reloads with slightly different configs
            for i in range(10):
                cfg = _make_swap_config(veth_pair, extra_ports=[9000 + i])
                gate.reload_config(cfg)
                time.sleep(0.2)

            # pktgate should still be alive
            assert gate.proc.poll() is None, "pktgate crashed during rapid reload"

            # Final config has port 9009 — verify it works
            pkt_ok = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9009)
            )
            assert send_and_check(pkt_ok, "tcp port 9009", expect_pass=True)

            # Port 9000 from first reload should NOT be in final config
            pkt_old = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9000)
            )
            assert send_and_check(pkt_old, "tcp port 9000", expect_pass=False)

        finally:
            gate.stop()
