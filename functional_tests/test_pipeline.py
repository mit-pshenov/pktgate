"""
Full pipeline functional tests — combinations across all layers.

Tests interesting cross-layer interactions:
  - L2 drop overrides valid L3+L4
  - L3 drop overrides valid L4
  - L4 default drop with valid L2+L3
  - All layers pass → packet delivered
  - Simultaneous correct/incorrect fields
"""

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw

from conftest import (
    send_and_check, CLIENT_IP4, FILTER_IP4, BLOCKED_IP4,
    CLIENT_IP6, FILTER_IP6, BLOCKED_IP6,
)


class TestPipelineAllPass:
    """Packets that should pass all layers."""

    def test_full_chain_tcp80(self, pktgate, veth_pair):
        """Known MAC + allowed IP + TCP/80 → PASS through all layers."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=40000, dport=80)
        )
        assert send_and_check(pkt, f"tcp port 80", expect_pass=True)

    def test_full_chain_tcp443(self, pktgate, veth_pair):
        """Known MAC + allowed IP + TCP/443 → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=40000, dport=443)
        )
        assert send_and_check(pkt, f"tcp port 443", expect_pass=True)

    def test_full_chain_udp53(self, pktgate, veth_pair):
        """Known MAC + allowed IP + UDP/53 (tag action) → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=40000, dport=53)
            / Raw(b"\x00" * 12)
        )
        assert send_and_check(pkt, f"udp port 53", expect_pass=True)

    def test_full_chain_ipv6_tcp80(self, pktgate, veth_pair):
        """Known MAC + allowed IPv6 + TCP/80 → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
            / TCP(sport=40000, dport=80)
        )
        assert send_and_check(pkt, f"tcp port 80", expect_pass=True)


class TestL2BlocksEverything:
    """Unknown MAC should block even with valid L3 + L4."""

    def test_unknown_mac_valid_ip_valid_port(self, pktgate, veth_pair):
        """Bad MAC + good IP + good port → DROP at L2."""
        _, filter_mac = veth_pair
        pkt = (
            Ether(src="de:ad:be:ef:00:01", dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"tcp port 80", expect_pass=False)


class TestL3BlocksValidL4:
    """Blocked IP should be dropped even with valid L4 port."""

    def test_blocked_ip_valid_port(self, pktgate, veth_pair):
        """Good MAC + blocked IP + good port → DROP at L3."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=BLOCKED_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP4}", expect_pass=False)

    def test_blocked_ipv6_valid_port(self, pktgate, veth_pair):
        """Good MAC + blocked IPv6 + good port → DROP at L3."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=BLOCKED_IP6, dst=FILTER_IP6)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP6}", expect_pass=False)


class TestL4DefaultDrop:
    """Valid L2 + L3, but no L4 rule → default DROP."""

    def test_valid_mac_ip_but_bad_port(self, pktgate, veth_pair):
        """Good MAC + good IP + unlisted port → DROP at L4."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"tcp port 9999", expect_pass=False)

    def test_icmp_default_drop(self, pktgate, veth_pair):
        """ICMP (not TCP/UDP) → no L4 rule → default DROP."""
        from scapy.all import ICMP
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / ICMP()
        )
        assert send_and_check(pkt, f"icmp", expect_pass=False)


class TestMultipleFailures:
    """Packets that fail at multiple layers simultaneously."""

    def test_all_wrong(self, pktgate, veth_pair):
        """Unknown MAC + unknown IP + unlisted port → DROP (at L2)."""
        _, filter_mac = veth_pair
        pkt = (
            Ether(src="de:ad:be:ef:00:01", dst=filter_mac)
            / IP(src="172.16.0.1", dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"tcp port 9999", expect_pass=False)

    def test_good_mac_all_else_wrong(self, pktgate, veth_pair):
        """Known MAC + unknown IP + unlisted port → L3 no match → L4 default DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src="172.16.0.1", dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"src 172.16.0.1", expect_pass=False)
