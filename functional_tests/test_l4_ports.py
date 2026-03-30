"""
Layer 4 functional tests — protocol + port filtering.

Tests that:
  - Allowed TCP ports pass
  - Allowed UDP ports pass (with tag action)
  - Unlisted ports are dropped (default DROP)
  - Wrong protocol for a port is dropped
  - Various port numbers near boundaries
"""

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw

from conftest import (
    send_and_check, CLIENT_IP4, FILTER_IP4,
)


class TestL4AllowedTcp:
    """TCP ports in the web_ports group (80, 443) should pass."""

    def test_tcp_80(self, pktgate, veth_pair):
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"tcp port 80", expect_pass=True)

    def test_tcp_443(self, pktgate, veth_pair):
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=443)
        )
        assert send_and_check(pkt, f"tcp port 443", expect_pass=True)

    def test_tcp_80_different_sport(self, pktgate, veth_pair):
        """Match is on dst_port only; different source port should still work."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=54321, dport=80)
        )
        assert send_and_check(pkt, f"tcp port 80", expect_pass=True)


class TestL4TagAction:
    """UDP/53 is configured with 'tag' action (DSCP EF) — packet should still pass."""

    def test_udp_53_passes(self, pktgate, veth_pair):
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=53)
            / Raw(b"\x00" * 20)  # DNS-like payload
        )
        assert send_and_check(pkt, f"udp port 53", expect_pass=True)


class TestL4BlockedPorts:
    """Ports not in config should be dropped by default action."""

    def test_tcp_22_dropped(self, pktgate, veth_pair):
        """SSH port not in web_ports → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=22)
        )
        assert send_and_check(pkt, f"tcp port 22", expect_pass=False)

    def test_tcp_8080_dropped(self, pktgate, veth_pair):
        """8080 is NOT in web_ports (only 80, 443) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=8080)
        )
        assert send_and_check(pkt, f"tcp port 8080", expect_pass=False)

    def test_tcp_9999_dropped(self, pktgate, veth_pair):
        """Random high port → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"tcp port 9999", expect_pass=False)

    def test_udp_1234_dropped(self, pktgate, veth_pair):
        """UDP port not 53 → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=1234)
            / Raw(b"test")
        )
        assert send_and_check(pkt, f"udp port 1234", expect_pass=False)


class TestL4WrongProtocol:
    """Port match is protocol-specific: TCP rule shouldn't match UDP and vice versa."""

    def test_udp_80_dropped(self, pktgate, veth_pair):
        """TCP/80 is allowed, but UDP/80 is NOT → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=80)
            / Raw(b"test")
        )
        assert send_and_check(pkt, f"udp port 80", expect_pass=False)

    def test_tcp_53_dropped(self, pktgate, veth_pair):
        """UDP/53 is allowed (tag), but TCP/53 is NOT → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=53)
        )
        assert send_and_check(pkt, f"tcp port 53", expect_pass=False)


class TestL4BoundaryPorts:
    """Test ports near the allowed values to catch off-by-one."""

    def test_tcp_79_dropped(self, pktgate, veth_pair):
        """Port 79 (one below 80) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=79)
        )
        assert send_and_check(pkt, f"tcp port 79", expect_pass=False)

    def test_tcp_81_dropped(self, pktgate, veth_pair):
        """Port 81 (one above 80) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=81)
        )
        assert send_and_check(pkt, f"tcp port 81", expect_pass=False)

    def test_tcp_442_dropped(self, pktgate, veth_pair):
        """Port 442 (one below 443) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=442)
        )
        assert send_and_check(pkt, f"tcp port 442", expect_pass=False)

    def test_tcp_444_dropped(self, pktgate, veth_pair):
        """Port 444 (one above 443) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=444)
        )
        assert send_and_check(pkt, f"tcp port 444", expect_pass=False)

    def test_udp_52_dropped(self, pktgate, veth_pair):
        """Port 52 (one below DNS 53) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=52)
            / Raw(b"test")
        )
        assert send_and_check(pkt, f"udp port 52", expect_pass=False)

    def test_udp_54_dropped(self, pktgate, veth_pair):
        """Port 54 (one above DNS 53) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=54)
            / Raw(b"test")
        )
        assert send_and_check(pkt, f"udp port 54", expect_pass=False)
