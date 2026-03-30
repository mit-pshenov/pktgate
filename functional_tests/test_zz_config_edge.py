"""
Config edge case tests.

Tests unusual but valid configurations:
  - default_behavior: "allow"
  - Multiple MACs in allow-list
  - Pipeline with only L2 (no L3/L4)
  - Large number of subnets / ports
"""

import copy

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw

from conftest import (
    send_and_check, PktgateProcess,
    CLIENT_IP4, FILTER_IP4,
    VETH_FILTER,
)


class TestDefaultAllow:
    """Config with default_behavior: 'allow'."""

    def test_unknown_traffic_passes(self, veth_pair):
        """With default=allow, unlisted port should pass."""
        client_mac, filter_mac = veth_pair
        config = {
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
            "default_behavior": "allow",
        }
        gate = PktgateProcess()
        try:
            gate.start(config)
            # TCP/9999 has no rule, but default=allow → PASS
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9999)
            )
            assert send_and_check(pkt, "tcp port 9999", expect_pass=True)
        finally:
            gate.stop()

    def test_explicit_drop_still_works(self, veth_pair):
        """Even with default=allow, explicit drop rules should still drop."""
        client_mac, filter_mac = veth_pair
        config = {
            "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
            "objects": {
                "mac_groups": {"allowed_macs": [client_mac]},
                "subnets": {"blocked": "10.99.0.99/32"},
            },
            "pipeline": {
                "layer_2": [{
                    "rule_id": 10,
                    "match": {"src_mac": "object:allowed_macs"},
                    "action": "allow",
                    "next_layer": "layer_3",
                }],
                "layer_3": [{
                    "rule_id": 100,
                    "match": {"src_ip": "object:blocked"},
                    "action": "drop",
                }],
            },
            "default_behavior": "allow",
        }
        gate = PktgateProcess()
        try:
            gate.start(config)
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src="10.99.0.99", dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )
            assert send_and_check(pkt, "src 10.99.0.99", expect_pass=False)
        finally:
            gate.stop()


class TestMultipleMacs:
    """Multiple MAC addresses in the allow-list."""

    def test_three_macs_all_allowed(self, veth_pair):
        """3 MACs in allow-list → all pass, 4th is dropped."""
        client_mac, filter_mac = veth_pair
        mac2 = "aa:bb:cc:00:00:02"
        mac3 = "aa:bb:cc:00:00:03"
        mac_bad = "de:ad:be:ef:00:01"

        config = {
            "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
            "objects": {
                "mac_groups": {"allowed": [client_mac, mac2, mac3]},
                "port_groups": {"web": [80]},
            },
            "pipeline": {
                "layer_2": [{
                    "rule_id": 10,
                    "match": {"src_mac": "object:allowed"},
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
        gate = PktgateProcess()
        try:
            gate.start(config)

            for mac in [client_mac, mac2, mac3]:
                pkt = (
                    Ether(src=mac, dst=filter_mac)
                    / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                    / TCP(sport=12345, dport=80)
                )
                assert send_and_check(pkt, "tcp port 80", expect_pass=True), \
                    f"MAC {mac} should be allowed"

            # Unknown MAC should be dropped
            pkt_bad = (
                Ether(src=mac_bad, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )
            assert send_and_check(pkt_bad, "tcp port 80", expect_pass=False)
        finally:
            gate.stop()


class TestManyRules:
    """Large configs with many subnets or ports."""

    def test_50_ports(self, veth_pair):
        """50 ports in L4 rule → all match, port 51 above max does not."""
        client_mac, filter_mac = veth_pair
        ports = list(range(5000, 5050))

        config = {
            "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
            "objects": {
                "mac_groups": {"allowed_macs": [client_mac]},
                "port_groups": {"many_ports": ports},
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
                    "match": {"protocol": "TCP", "dst_port": "object:many_ports"},
                    "action": "allow",
                }],
            },
            "default_behavior": "drop",
        }
        gate = PktgateProcess()
        try:
            gate.start(config)

            # First port should pass
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=5000)
            )
            assert send_and_check(pkt, "tcp port 5000", expect_pass=True)

            # Last port should pass
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=5049)
            )
            assert send_and_check(pkt, "tcp port 5049", expect_pass=True)

            # Port just outside range should be dropped
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=5050)
            )
            assert send_and_check(pkt, "tcp port 5050", expect_pass=False)
        finally:
            gate.stop()

    def test_100_subnets(self, veth_pair):
        """100 /24 subnets in L3 → spot-check a few."""
        client_mac, filter_mac = veth_pair
        # Generate 100 subnets: 10.{1..100}.0.0/24
        subnets = {f"net_{i}": f"10.{i}.0.0/24" for i in range(1, 101)}

        l3_rules = []
        for idx, name in enumerate(subnets.keys()):
            l3_rules.append({
                "rule_id": 100 + idx,
                "match": {"src_ip": f"object:{name}"},
                "action": "allow",
                "next_layer": "layer_4",
            })

        config = {
            "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
            "objects": {
                "subnets": subnets,
                "mac_groups": {"allowed_macs": [client_mac]},
                "port_groups": {"web": [80]},
            },
            "pipeline": {
                "layer_2": [{
                    "rule_id": 10,
                    "match": {"src_mac": "object:allowed_macs"},
                    "action": "allow",
                    "next_layer": "layer_3",
                }],
                "layer_3": l3_rules,
                "layer_4": [{
                    "rule_id": 2000,
                    "match": {"protocol": "TCP", "dst_port": "object:web"},
                    "action": "allow",
                }],
            },
            "default_behavior": "drop",
        }
        gate = PktgateProcess()
        try:
            gate.start(config)

            # Spot-check: 10.1.0.5, 10.50.0.5, 10.100.0.5 should pass
            for subnet_idx in [1, 50, 100]:
                src = f"10.{subnet_idx}.0.5"
                pkt = (
                    Ether(src=client_mac, dst=filter_mac)
                    / IP(src=src, dst=FILTER_IP4)
                    / TCP(sport=12345, dport=80)
                )
                assert send_and_check(pkt, f"src {src}", expect_pass=True), \
                    f"10.{subnet_idx}.0.0/24 should be allowed"

            # 10.200.0.5 is NOT in config → L3 no match → L4 TCP/80 allowed → PASS
            # (same as before: L3 no-match delegates to L4)

        finally:
            gate.stop()
