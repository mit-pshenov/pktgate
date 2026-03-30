"""
Layer 3 functional tests — IPv4/IPv6 subnet filtering.

Tests that:
  - Packets from allowed subnets pass L3
  - Packets from blocked IPs/subnets are dropped at L3
  - More specific rules take priority (LPM)
  - IPv6 rules work correctly
  - Non-IP protocols are handled
"""

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ARP, Raw

from conftest import (
    send_and_check, CLIENT_IP4, FILTER_IP4, BLOCKED_IP4,
    CLIENT_IP6, FILTER_IP6, BLOCKED_IP6,
)


class TestL3AllowedSubnet:
    """Packets from the allowed client subnet should pass L3."""

    def test_client_ip_tcp80(self, pktgate, veth_pair):
        """Client IP in allowed subnet + TCP/80 → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 80", expect_pass=True)

    def test_client_ip_tcp443(self, pktgate, veth_pair):
        """Client IP + TCP/443 → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=443)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and tcp port 443", expect_pass=True)


class TestL3BlockedHost:
    """Packets from the blocked /32 host should be dropped at L3."""

    def test_blocked_ip_tcp80(self, pktgate, veth_pair):
        """Blocked IP + TCP/80 → DROP at L3 (never reaches L4)."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=BLOCKED_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP4} and tcp port 80", expect_pass=False)

    def test_blocked_ip_tcp443(self, pktgate, veth_pair):
        """Blocked IP + TCP/443 → also DROP at L3."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=BLOCKED_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=443)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP4} and tcp port 443", expect_pass=False)

    def test_blocked_ip_udp_dns(self, pktgate, veth_pair):
        """Blocked IP + UDP/53 → DROP at L3."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=BLOCKED_IP4, dst=FILTER_IP4)
            / UDP(sport=12345, dport=53)
            / Raw(b"\x00" * 12)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP4} and udp port 53", expect_pass=False)


class TestL3LpmPriority:
    """LPM: more specific prefix (/32) should take priority over /24."""

    def test_blocked_32_overrides_allowed_24(self, pktgate, veth_pair):
        """10.99.0.99/32 DROP should override 10.99.0.0/24 ALLOW."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=BLOCKED_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP4}", expect_pass=False)

    def test_adjacent_ip_still_allowed(self, pktgate, veth_pair):
        """10.99.0.98 (not the blocked /32) should still pass via /24 rule."""
        client_mac, filter_mac = veth_pair
        near_ip = "10.99.0.98"
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=near_ip, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {near_ip} and tcp port 80", expect_pass=True)


class TestL3UnknownSubnet:
    """IPs outside any configured subnet: L3 delegates to L4 (no implicit drop at L3)."""

    def test_external_ip_allowed_port_passes(self, pktgate, veth_pair):
        """172.16.0.1 → no L3 match → tail-call to L4 → TCP/80 ALLOW → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src="172.16.0.1", dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "src 172.16.0.1 and tcp port 80", expect_pass=True)

    def test_external_ip_blocked_port_dropped(self, pktgate, veth_pair):
        """172.16.0.1 → no L3 match → L4 → TCP/9999 no rule → default DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src="172.16.0.1", dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, "src 172.16.0.1 and tcp port 9999", expect_pass=False)

    def test_rfc5737_test_net_blocked_port(self, pktgate, veth_pair):
        """192.0.2.100 (TEST-NET-1) → no L3 match → L4 → no rule → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src="192.0.2.100", dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, "src 192.0.2.100", expect_pass=False)


class TestL3IPv6:
    """IPv6 subnet rules."""

    def test_ipv6_allowed_prefix(self, pktgate, veth_pair):
        """fd00::2 in fd00::/64 → ALLOW → L4 TCP/80 → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP6} and tcp port 80", expect_pass=True)

    def test_ipv6_blocked_prefix(self, pktgate, veth_pair):
        """fd00:dead::1 in fd00:dead::/48 → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=BLOCKED_IP6, dst=FILTER_IP6)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"src {BLOCKED_IP6}", expect_pass=False)

    def test_ipv6_unknown_prefix_allowed_port(self, pktgate, veth_pair):
        """2001:db8::1 → no L3 match → L4 → TCP/80 ALLOW → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src="2001:db8::1", dst=FILTER_IP6)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "ip6", expect_pass=True)

    def test_ipv6_unknown_prefix_blocked_port(self, pktgate, veth_pair):
        """2001:db8::1 → no L3 match → L4 → TCP/9999 no rule → default DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src="2001:db8::1", dst=FILTER_IP6)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, "ip6", expect_pass=False)


class TestL3NonIP:
    """Non-IP protocols should be handled by L3 (dropped for non-IPv4/IPv6)."""

    def test_arp_dropped(self, pktgate, veth_pair):
        """ARP frame → L3 drops non-IP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac, type=0x0806)
            / ARP(psrc=CLIENT_IP4, pdst=FILTER_IP4)
        )
        assert send_and_check(pkt, "arp", expect_pass=False)
