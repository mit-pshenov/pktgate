"""
Layer 2 functional tests — MAC address filtering.

Tests that:
  - Packets from allowed MACs pass through L2
  - Packets from unknown MACs are dropped at L2
  - Broadcast/multicast MACs are dropped
  - Spoofed MACs (correct IP but wrong MAC) are dropped
"""

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw

from conftest import (
    send_and_check, CLIENT_IP4, FILTER_IP4,
    NS_CLIENT, VETH_CLIENT,
)


class TestL2KnownMac:
    """Packets from the allowed client MAC should pass L2."""

    def test_tcp_from_known_mac(self, pktgate, veth_pair):
        """Known MAC + valid TCP → should pass (if L3/L4 also allow)."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=True)

    def test_udp_dns_from_known_mac(self, pktgate, veth_pair):
        """Known MAC + UDP/53 → should pass (tag action still passes)."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=53)
            / Raw(b"\x00" * 12)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and udp port 53", expect_pass=True)

    def test_icmp_from_known_mac(self, pktgate, veth_pair):
        """Known MAC + ICMP → passes L2, L3 allows subnet, but L4 has no ICMP rule → default DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / ICMP()
        )
        # ICMP has no L4 rule → default drop
        assert send_and_check(pkt, f"src {CLIENT_IP4} and icmp", expect_pass=False)


class TestL2UnknownMac:
    """Packets from MACs not in the allow-list should be dropped at L2."""

    def test_random_mac_tcp80(self, pktgate, veth_pair):
        """Unknown MAC with valid TCP/80 → dropped at L2 despite valid L3+L4."""
        _, filter_mac = veth_pair
        spoofed_mac = "de:ad:be:ef:00:01"
        pkt = (
            Ether(src=spoofed_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=False)

    def test_another_random_mac(self, pktgate, veth_pair):
        """Different unknown MAC → also dropped."""
        _, filter_mac = veth_pair
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:ff", dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=False)

    def test_zero_mac(self, pktgate, veth_pair):
        """All-zero MAC → dropped."""
        _, filter_mac = veth_pair
        pkt = (
            Ether(src="00:00:00:00:00:00", dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=False)


class TestL2SpecialMacs:
    """Broadcast and multicast MACs should be dropped (not in allow-list)."""

    def test_broadcast_src_mac(self, pktgate, veth_pair):
        """Broadcast source MAC → not in allow-list → DROP."""
        _, filter_mac = veth_pair
        pkt = (
            Ether(src="ff:ff:ff:ff:ff:ff", dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=False)

    def test_multicast_src_mac(self, pktgate, veth_pair):
        """Multicast source MAC → dropped."""
        _, filter_mac = veth_pair
        pkt = (
            Ether(src="01:00:5e:00:00:01", dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=False)
