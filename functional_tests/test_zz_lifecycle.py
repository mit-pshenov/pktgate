"""
Process lifecycle tests.

Verifies signal handling and process management:
  - SIGTERM graceful shutdown (XDP detached → traffic passes unfiltered)
  - SIGHUP triggers config reload
  - SIGUSR1 stats dump without side effects
  - Restart after stop → XDP re-attached
"""

import signal
import time

import pytest
from scapy.all import Ether, IP, TCP

from conftest import (
    send_and_check, PktgateProcess,
    CLIENT_IP4, FILTER_IP4, VETH_FILTER,
)


def _simple_config(client_mac):
    """Minimal config: allow client MAC + TCP/80, drop rest."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "objects": {
            "mac_groups": {"allowed_macs": [client_mac]},
            "port_groups": {"web": [80]},
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


class TestSigterm:
    """SIGTERM should gracefully shutdown and detach XDP."""

    def test_sigterm_detaches_xdp(self, veth_pair):
        """After SIGTERM, XDP is detached → all traffic passes unfiltered."""
        client_mac, filter_mac = veth_pair
        gate = PktgateProcess()
        try:
            gate.start(_simple_config(client_mac))

            # TCP/9999 should be blocked while filter is active
            pkt_blocked = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9999)
            )
            assert send_and_check(pkt_blocked, "tcp port 9999", expect_pass=False)

            # Stop pktgate → XDP detached
            gate.stop()
            time.sleep(0.5)

            # Now the same packet should pass (no filter)
            assert send_and_check(pkt_blocked, "tcp port 9999", expect_pass=True)
        finally:
            gate.stop()


class TestSighup:
    """SIGHUP should trigger config reload (alternative to inotify)."""

    def test_sighup_reloads_config(self, veth_pair):
        """Write new config, send SIGHUP → new rules applied."""
        import copy
        client_mac, filter_mac = veth_pair
        gate = PktgateProcess()
        try:
            config = _simple_config(client_mac)
            gate.start(config)

            # TCP/8080 blocked initially
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=8080)
            )
            assert send_and_check(pkt, "tcp port 8080", expect_pass=False)

            # Update config to add 8080
            new_config = copy.deepcopy(config)
            new_config["objects"]["port_groups"]["web"] = [80, 8080]
            import json
            with open(gate.config_path, "w") as f:
                json.dump(new_config, f, indent=2)

            # Send SIGHUP instead of waiting for inotify
            gate.proc.send_signal(signal.SIGHUP)
            time.sleep(1.0)

            # Now TCP/8080 should pass
            assert send_and_check(pkt, "tcp port 8080", expect_pass=True)
        finally:
            gate.stop()


class TestSigusr1:
    """SIGUSR1 should dump stats without affecting filter behavior."""

    def test_sigusr1_no_side_effects(self, veth_pair):
        """Send SIGUSR1, verify filter still works correctly after."""
        client_mac, filter_mac = veth_pair
        gate = PktgateProcess()
        try:
            gate.start(_simple_config(client_mac))

            pkt_allow = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )
            pkt_block = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9999)
            )

            # Verify before SIGUSR1
            assert send_and_check(pkt_allow, "tcp port 80", expect_pass=True)

            # Send SIGUSR1 multiple times
            for _ in range(5):
                gate.proc.send_signal(signal.SIGUSR1)
                time.sleep(0.1)

            # Process should still be alive
            assert gate.proc.poll() is None, "pktgate crashed after SIGUSR1"

            # Filter should still work correctly
            assert send_and_check(pkt_allow, "tcp port 80", expect_pass=True)
            assert send_and_check(pkt_block, "tcp port 9999", expect_pass=False)
        finally:
            gate.stop()


class TestRestart:
    """Restart after stop → XDP re-attached."""

    def test_restart_reattaches_xdp(self, veth_pair):
        """Stop pktgate, start again → filter active again."""
        client_mac, filter_mac = veth_pair
        gate = PktgateProcess()
        try:
            config = _simple_config(client_mac)
            gate.start(config)

            pkt_block = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9999)
            )

            # Should be blocked
            assert send_and_check(pkt_block, "tcp port 9999", expect_pass=False)

            # Stop
            gate.stop()
            time.sleep(0.5)

            # Should pass now (no filter)
            assert send_and_check(pkt_block, "tcp port 9999", expect_pass=True)

            # Restart
            gate.start(config)

            # Should be blocked again
            assert send_and_check(pkt_block, "tcp port 9999", expect_pass=False)
        finally:
            gate.stop()
