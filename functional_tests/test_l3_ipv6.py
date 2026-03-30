"""
IPv6-specific functional tests — fragments and extension headers.

Tests that:
  - IPv6 packets with Fragment Header are dropped at L3
  - IPv6 extension headers (Hop-by-Hop, Routing, Destination) are
    correctly skipped in L4, allowing TCP/UDP matching to work
  - Fragment headers after extension headers are also caught
"""

import pytest
from scapy.all import (
    Ether, IPv6, TCP, UDP, Raw,
    IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting,
    IPv6ExtHdrDestOpt,
    PadN,
)

from conftest import (
    send_and_check, CLIENT_IP6, FILTER_IP6, BLOCKED_IP6,
)


class TestIPv6FragmentDrop:
    """IPv6 Fragment Header (nexthdr=44) should be dropped at L3."""

    def test_fragment_header_tcp_dropped(self, pktgate, veth_pair):
        """IPv6/FragmentHeader/TCP → DROP at L3."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=0x1234)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "ip6", expect_pass=False)

    def test_fragment_header_udp_dropped(self, pktgate, veth_pair):
        """IPv6/FragmentHeader/UDP → DROP at L3."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
            / IPv6ExtHdrFragment(offset=0, m=1, id=0x5678)
            / UDP(sport=12345, dport=53)
            / Raw(b"\x00" * 12)
        )
        assert send_and_check(pkt, "ip6", expect_pass=False)

    def test_nonfirst_fragment_dropped(self, pktgate, veth_pair):
        """Non-first IPv6 fragment (offset > 0) → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
            / IPv6ExtHdrFragment(offset=100, m=0, id=0xABCD)
            / Raw(b"\x00" * 64)
        )
        assert send_and_check(pkt, "ip6", expect_pass=False)


class TestIPv6ExtensionHeaders:
    """Extension headers should be skipped in L4 to find TCP/UDP."""

    def test_hopbyhop_then_tcp80_pass(self, pktgate, veth_pair):
        """IPv6/HopByHop/TCP:80 → ext header skipped, L4 matches TCP/80 → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=0)
            / IPv6ExtHdrHopByHop(nh=6, options=[PadN(optdata=b"\x00" * 4)])
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "ip6", expect_pass=True)

    def test_routing_then_tcp443_pass(self, pktgate, veth_pair):
        """IPv6/RoutingHeader/TCP:443 → ext header skipped → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=43)
            / IPv6ExtHdrRouting(nh=6, addresses=[])
            / TCP(sport=12345, dport=443)
        )
        assert send_and_check(pkt, "ip6", expect_pass=True)

    def test_destopt_then_tcp80_pass(self, pktgate, veth_pair):
        """IPv6/DestinationOptions/TCP:80 → ext header skipped → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=60)
            / IPv6ExtHdrDestOpt(nh=6, options=[PadN(optdata=b"\x00" * 4)])
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "ip6", expect_pass=True)

    def test_two_ext_headers_then_tcp80_pass(self, pktgate, veth_pair):
        """IPv6/HopByHop/DestOpt/TCP:80 → two ext headers skipped → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=0)
            / IPv6ExtHdrHopByHop(nh=60, options=[PadN(optdata=b"\x00" * 4)])
            / IPv6ExtHdrDestOpt(nh=6, options=[PadN(optdata=b"\x00" * 4)])
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "ip6", expect_pass=True)

    def test_ext_header_then_blocked_port_dropped(self, pktgate, veth_pair):
        """IPv6/HopByHop/TCP:9999 → ext header skipped → L4 no rule → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=0)
            / IPv6ExtHdrHopByHop(nh=6, options=[PadN(optdata=b"\x00" * 4)])
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, "ip6", expect_pass=False)

    def test_ext_header_then_udp53_pass(self, pktgate, veth_pair):
        """IPv6/DestOpt/UDP:53 → ext header skipped → L4 tag rule → PASS."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=60)
            / IPv6ExtHdrDestOpt(nh=17, options=[PadN(optdata=b"\x00" * 4)])
            / UDP(sport=12345, dport=53)
            / Raw(b"\x00" * 12)
        )
        assert send_and_check(pkt, "ip6", expect_pass=True)


class TestIPv6FragmentAfterExtHeaders:
    """Fragment header appearing after extension headers should also be caught."""

    def test_hopbyhop_then_fragment_dropped(self, pktgate, veth_pair):
        """IPv6/HopByHop(nh=44)/Fragment/TCP → L3 sees nexthdr=0 (not 44),
        passes to L4 which skips HopByHop, encounters fragment → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=FILTER_IP6, nh=0)
            / IPv6ExtHdrHopByHop(nh=44, options=[PadN(optdata=b"\x00" * 4)])
            / IPv6ExtHdrFragment(offset=0, m=1, id=0xDEAD)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, "ip6", expect_pass=False)
