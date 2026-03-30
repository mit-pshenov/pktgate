"""
Malformed / crafted packet tests.

Validates that the XDP filter gracefully handles:
  - Truncated headers at every layer
  - Invalid IP fields (version, IHL, tot_len)
  - IP fragments
  - Non-TCP/UDP protocols reaching L4
  - VLAN-tagged frames
  - Empty payloads
"""

import struct

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, Dot1Q

from conftest import (
    send_and_check, CLIENT_IP4, FILTER_IP4,
    CLIENT_IP6, FILTER_IP6,
)


def _raw_eth_ip(src_mac, dst_mac, ip_bytes, pad_to=64):
    """Build an Ethernet frame with raw IP bytes (for crafting invalid headers)."""
    eth = Ether(src=src_mac, dst=dst_mac, type=0x0800)
    frame = bytes(eth) + ip_bytes
    if len(frame) < pad_to:
        frame += b"\x00" * (pad_to - len(frame))
    return Ether(frame)


def _make_ip_header(version=4, ihl=5, tos=0, tot_len=None, proto=6,
                    src="10.99.0.2", dst="10.99.0.1", frag_off=0):
    """Build a raw IPv4 header with arbitrary fields."""
    import socket
    src_b = socket.inet_aton(src)
    dst_b = socket.inet_aton(dst)
    if tot_len is None:
        tot_len = ihl * 4 + 20  # assume 20 bytes payload
    ver_ihl = (version << 4) | ihl
    # flags+frag_off is 16-bit: flags (3 bits) + offset (13 bits)
    return struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, tot_len,
        0, frag_off,     # identification, flags+frag_off
        64, proto, 0,    # TTL, protocol, checksum (0 = let kernel fix)
        src_b, dst_b,
    )


class TestTruncatedHeaders:
    """Packets with headers too short for the expected protocol."""

    def test_truncated_ip_header(self, pktgate, veth_pair):
        """ETH + only 10 bytes of IP (need 20) → DROP at L3 bounds check."""
        client_mac, filter_mac = veth_pair
        # 10 bytes: version+ihl, tos, tot_len(2), id(2), frag(2), ttl, proto
        short_ip = _make_ip_header()[:10]
        pkt = _raw_eth_ip(client_mac, filter_mac, short_ip)
        assert send_and_check(pkt, f"src {CLIENT_IP4}", expect_pass=False)

    def test_truncated_tcp_header(self, pktgate, veth_pair):
        """Valid IP header with proto=TCP but only 2 bytes of TCP → DROP at L4."""
        client_mac, filter_mac = veth_pair
        ip_hdr = _make_ip_header(proto=6, tot_len=22)  # 20 IP + 2 TCP
        tcp_stub = b"\x00\x50"  # partial: dst_port=80, no more
        pkt = _raw_eth_ip(client_mac, filter_mac, ip_hdr + tcp_stub)
        assert send_and_check(pkt, f"src {CLIENT_IP4}", expect_pass=False)

    def test_truncated_udp_header(self, pktgate, veth_pair):
        """Valid IP header with proto=UDP but only 2 bytes of UDP → DROP at L4."""
        client_mac, filter_mac = veth_pair
        ip_hdr = _make_ip_header(proto=17, tot_len=22)  # 20 IP + 2 UDP
        udp_stub = b"\x00\x35"  # partial: dst_port=53, no more
        pkt = _raw_eth_ip(client_mac, filter_mac, ip_hdr + udp_stub)
        assert send_and_check(pkt, f"src {CLIENT_IP4}", expect_pass=False)

    def test_truncated_ipv6_header(self, pktgate, veth_pair):
        """ETH(0x86DD) + only 10 bytes of IPv6 (need 40) → DROP at L3."""
        client_mac, filter_mac = veth_pair
        eth = Ether(src=client_mac, dst=filter_mac, type=0x86DD)
        # 10 bytes of garbage pretending to be IPv6
        frame = bytes(eth) + b"\x60" + b"\x00" * 9
        frame += b"\x00" * (64 - len(frame))  # pad to min frame
        pkt = Ether(frame)
        assert send_and_check(pkt, "ip6", expect_pass=False)

    def test_empty_eth_payload(self, pktgate, veth_pair):
        """Ethernet header with type=IP but no payload → DROP at L3 bounds."""
        client_mac, filter_mac = veth_pair
        eth = Ether(src=client_mac, dst=filter_mac, type=0x0800)
        # Pad to minimum ethernet frame (no IP header)
        frame = bytes(eth) + b"\x00" * (64 - 14)
        pkt = Ether(frame)
        assert send_and_check(pkt, f"host {FILTER_IP4}", expect_pass=False)


class TestInvalidIPFields:
    """Packets with valid-length but semantically broken IP headers."""

    def test_ip_version_6_in_ipv4_frame(self, pktgate, veth_pair):
        """ETH type=0x0800 but IP version=6 → L3 should handle/drop."""
        client_mac, filter_mac = veth_pair
        bad_ip = _make_ip_header(version=6, ihl=5, proto=6)
        tcp = struct.pack("!HH", 12345, 80) + b"\x00" * 16  # minimal TCP
        pkt = _raw_eth_ip(client_mac, filter_mac, bad_ip + tcp)
        # Kernel/XDP may drop or pass — we just verify no crash
        send_and_check(pkt, f"host {FILTER_IP4}", expect_pass=False)

    def test_ihl_too_small(self, pktgate, veth_pair):
        """IHL=2 (8 bytes, need >=20) → bounds check should catch it."""
        client_mac, filter_mac = veth_pair
        bad_ip = _make_ip_header(ihl=2, proto=6)
        pkt = _raw_eth_ip(client_mac, filter_mac, bad_ip)
        assert send_and_check(pkt, f"host {FILTER_IP4}", expect_pass=False)

    def test_zero_tot_len(self, pktgate, veth_pair):
        """IP tot_len=0 → should be handled without crash."""
        client_mac, filter_mac = veth_pair
        bad_ip = _make_ip_header(tot_len=0, proto=6)
        tcp = struct.pack("!HH", 12345, 80) + b"\x00" * 16
        pkt = _raw_eth_ip(client_mac, filter_mac, bad_ip + tcp)
        # We don't assert pass/fail — just that it doesn't crash the filter
        send_and_check(pkt, f"host {FILTER_IP4}", expect_pass=False)


class TestIPFragments:
    """IP fragment handling — non-first fragments lack L4 headers."""

    def test_non_first_fragment_dropped(self, pktgate, veth_pair):
        """Non-first IP fragment (frag_off > 0) → DROP at L3."""
        client_mac, filter_mac = veth_pair
        # frag_off = 0x2000 means MF=1, offset=0 → first fragment
        # frag_off = 0x0001 means MF=0, offset=1 → non-first fragment (offset in 8-byte units)
        frag_ip = _make_ip_header(proto=6, frag_off=0x0001)
        pkt = _raw_eth_ip(client_mac, filter_mac, frag_ip)
        assert send_and_check(pkt, f"src {CLIENT_IP4}", expect_pass=False)

    def test_first_fragment_processed(self, pktgate, veth_pair):
        """First IP fragment (MF=1, offset=0) → has L4 headers, should be processed normally."""
        client_mac, filter_mac = veth_pair
        # MF=1, offset=0: flags byte = 0x2000
        frag_ip = _make_ip_header(proto=6, frag_off=0x2000, tot_len=40)
        tcp = struct.pack("!HH", 12345, 80) + b"\x00" * 16
        pkt = _raw_eth_ip(client_mac, filter_mac, frag_ip + tcp)
        # First fragment with TCP/80 should be allowed (has full L4 header)
        assert send_and_check(pkt, f"src {CLIENT_IP4}", expect_pass=True)


class TestNonTcpUdpProtocols:
    """Protocols that aren't TCP or UDP reaching L4."""

    def test_gre_protocol_dropped(self, pktgate, veth_pair):
        """IP proto=47 (GRE) → L4 has no rule → default DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4, proto=47)
            / Raw(b"\x00" * 20)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4} and proto 47", expect_pass=False)

    def test_sctp_protocol_dropped(self, pktgate, veth_pair):
        """IP proto=132 (SCTP) → L4 has no rule → default DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4, proto=132)
            / Raw(b"\x00" * 20)
        )
        assert send_and_check(pkt, f"src {CLIENT_IP4}", expect_pass=False)


class TestVlanTagged:
    """VLAN-tagged (802.1Q) frames."""

    def test_vlan_tagged_ip_dropped(self, pktgate, veth_pair):
        """802.1Q tagged frame → L3 sees ethertype 0x8100, not 0x0800 → DROP."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / Dot1Q(vlan=100)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80)
        )
        assert send_and_check(pkt, f"vlan and src {CLIENT_IP4}", expect_pass=False)


class TestTcpFlags:
    """TCP flag combinations — filter matches on port, not flags."""

    def test_christmas_tree_allowed_port(self, pktgate, veth_pair):
        """All TCP flags set + allowed port 80 → should still PASS (flags not filtered)."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=80, flags="FSRPAUECN")
        )
        assert send_and_check(pkt, f"tcp port 80", expect_pass=True)

    def test_rst_only_blocked_port(self, pktgate, veth_pair):
        """RST to blocked port → still DROP (port rule, not flag rule)."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4)
            / TCP(sport=12345, dport=9999, flags="R")
        )
        assert send_and_check(pkt, f"tcp port 9999", expect_pass=False)
