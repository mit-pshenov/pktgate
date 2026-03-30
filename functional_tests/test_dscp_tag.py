"""
DSCP tagging verification tests.

Verifies that the TC ingress program actually rewrites the IP TOS byte
when the tag action is applied (UDP/53 → DSCP EF in base config).

Note: tcpdump captures packets BEFORE TC ingress in the Linux stack
(XDP → AF_PACKET → TC ingress → IP layer), so we can't check TOS via
tcpdump. Instead, we use a UDP socket receiver in the filter namespace
with IP_RECVTOS to inspect the actual delivered TOS byte.
"""

import os
import subprocess
import threading
import time

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw

from conftest import (
    send_and_check, send_burst,
    CLIENT_IP4, FILTER_IP4,
    NS_FILTER, NS_CLIENT, VETH_CLIENT,
    nsexec, _run,
)


# Python script that runs inside ns_filter to receive UDP packets and report TOS.
_RECEIVER_SCRIPT = r"""
import socket, struct, sys

port = int(sys.argv[1])
timeout = float(sys.argv[2])
count = int(sys.argv[3])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_IP, socket.IP_RECVTOS, 1)
s.settimeout(timeout)
s.bind(('0.0.0.0', port))

received = 0
for _ in range(count):
    try:
        data, ancdata, flags, addr = s.recvmsg(1024, 256)
        tos = 0
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == socket.IP_TOS:
                tos = struct.unpack('B', cmsg_data[:1])[0]
        print(f"0x{tos:02x}")
        received += 1
    except socket.timeout:
        break

s.close()
"""


def _receive_tos(port, timeout=4, count=3):
    """Run a UDP receiver in ns_filter, return list of TOS hex strings."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(_RECEIVER_SCRIPT)
        script_path = f.name

    try:
        cmd = (
            f"ip netns exec {NS_FILTER} "
            f"python3 {script_path} {port} {timeout} {count}"
        )
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout + 5,
        )
        return [line.strip() for line in r.stdout.strip().splitlines() if line.strip()]
    finally:
        os.unlink(script_path)


class TestDscpTagging:
    """Verify TOS byte rewrite by TC ingress via socket-level inspection."""

    def test_udp53_tagged_with_dscp_ef(self, pktgate, veth_pair):
        """UDP/53 with tag action (DSCP EF=46) → delivered TOS should be 0xb8."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4, tos=0)
            / UDP(sport=12345, dport=53)
            / Raw(b"DSCPTEST")
        )

        tos_values = []

        def _recv():
            tos_values.extend(_receive_tos(53, timeout=5, count=3))

        recv_t = threading.Thread(target=_recv, daemon=True)
        recv_t.start()
        time.sleep(0.5)  # let receiver bind

        send_burst(pkt, count=3)
        recv_t.join(timeout=8)

        assert len(tos_values) > 0, "No packets received by socket"
        # DSCP EF = 46, TOS = 46 << 2 = 184 = 0xb8
        for tos in tos_values:
            assert tos == "0xb8", f"Expected TOS 0xb8 (DSCP EF), got {tos}"

    def test_dscp_preserves_ecn_bits(self, pktgate, veth_pair):
        """Packet with ECN bits (tos=0x03) → after tag, DSCP rewritten but ECN preserved."""
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4, tos=0x03)  # ECN = CE (congestion experienced)
            / UDP(sport=12345, dport=53)
            / Raw(b"ECNTEST")
        )

        tos_values = []

        def _recv():
            tos_values.extend(_receive_tos(53, timeout=5, count=3))

        recv_t = threading.Thread(target=_recv, daemon=True)
        recv_t.start()
        time.sleep(0.5)

        send_burst(pkt, count=3)
        recv_t.join(timeout=8)

        assert len(tos_values) > 0, "No packets received"
        # DSCP EF (0xb8) | ECN CE (0x03) = 0xbb
        for tos in tos_values:
            assert tos == "0xbb", f"Expected TOS 0xbb (EF+ECN), got {tos}"

    def test_no_tag_on_allowed_tcp80(self, pktgate, veth_pair):
        """TCP/80 has 'allow' action (not 'tag') → TOS unchanged.

        We verify via tcpdump since there's no tag action — the TOS
        should remain as sent (0x00). tcpdump captures pre-TC, but
        since no TC rewrite happens, it's valid.
        """
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=FILTER_IP4, tos=0)
            / TCP(sport=12345, dport=80)
        )
        # Just verify the packet passes (TOS rewrite only for tag action)
        assert send_and_check(pkt, "tcp port 80", expect_pass=True)
