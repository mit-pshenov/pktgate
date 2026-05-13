"""
Layer 3 dst_ip functional tests.

dst_ip / dst_ip6 became real L3 match fields (separate destination LPM
maps in the data plane). These tests assert the end-to-end behaviour on
real veth + scapy traffic:

  * packet destined to a matched dst subnet is dropped at L3
  * packet destined outside that subnet still passes through
  * source rules win over destination rules when both apply

Standalone gate (PktgateProcess) — the session-scope pktgate fixture
loads a different config that doesn't have dst_ip rules.
"""

import pytest
from scapy.all import Ether, IP, IPv6, TCP

from conftest import (
    send_and_check,
    PktgateProcess,
    CLIENT_IP4, FILTER_IP4,
    CLIENT_IP6, FILTER_IP6,
    VETH_FILTER,
)


# Destination subnets that the filter will block.
DST_BLOCK_NET4 = "10.20.0.0/16"
DST_BLOCK_IP4  = "10.20.5.5"
DST_PASS_IP4   = "10.30.5.5"  # outside DST_BLOCK_NET4

DST_BLOCK_NET6 = "2001:db8:beef::/48"
DST_BLOCK_IP6  = "2001:db8:beef::1"
DST_PASS_IP6   = "2001:db8:cafe::1"


def _dst_only_config(veth_pair):
    client_mac, _ = veth_pair
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "objects": {
            "mac_groups": {"clients": [client_mac]},
            "subnets":  {"blocked_dst_v4": DST_BLOCK_NET4},
            "subnets6": {"blocked_dst_v6": DST_BLOCK_NET6},
        },
        "pipeline": {
            "layer_2": [{
                "rule_id": 10,
                "match": {"src_mac": "object:clients"},
                "action": "allow",
                "next_layer": "layer_3",
            }],
            "layer_3": [
                {
                    "rule_id": 100,
                    "description": "Drop traffic to internal v4 subnet",
                    "match": {"dst_ip": "object:blocked_dst_v4"},
                    "action": "drop",
                },
                {
                    "rule_id": 110,
                    "description": "Drop traffic to internal v6 subnet",
                    "match": {"dst_ip6": "object6:blocked_dst_v6"},
                    "action": "drop",
                },
            ],
        },
        "default_behavior": "allow",
    }


@pytest.fixture(scope="class")
def dst_ip_gate(veth_pair):
    """Per-class gate with dst_ip-only config. Slower to set up than the
    session-scope `pktgate` fixture but lets the test class own its config."""
    gate = PktgateProcess()
    gate.start(_dst_only_config(veth_pair))
    yield gate
    gate.stop()


class TestL3DstIp:
    def test_dst_ip_in_subnet_dropped(self, dst_ip_gate, veth_pair):
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=DST_BLOCK_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"dst host {DST_BLOCK_IP4}",
                              expect_pass=False)

    def test_dst_ip_outside_subnet_passes(self, dst_ip_gate, veth_pair):
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IP(src=CLIENT_IP4, dst=DST_PASS_IP4)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"dst host {DST_PASS_IP4}",
                              expect_pass=True)

    def test_dst_ip6_in_subnet_dropped(self, dst_ip_gate, veth_pair):
        client_mac, filter_mac = veth_pair
        pkt = (
            Ether(src=client_mac, dst=filter_mac)
            / IPv6(src=CLIENT_IP6, dst=DST_BLOCK_IP6)
            / TCP(sport=12345, dport=9999)
        )
        assert send_and_check(pkt, f"ip6 dst host {DST_BLOCK_IP6}",
                              expect_pass=False)


class TestL3DstIpReload:
    """B4: reload lifecycle for dst_ip rules. Guards lpm_keys_dst tracking
    in GenerationManager — a missed bookkeeping would either leave stale
    rules across reloads (silent rule mixing) or fail to populate the new
    generation's dst map (silent rule disappearance)."""

    def test_dst_rule_appears_then_disappears_across_reloads(self, veth_pair):
        client_mac, filter_mac = veth_pair
        gate = PktgateProcess()
        try:
            # Start WITHOUT any dst rule — packet to "blocked" subnet must
            # pass (default_behavior=allow).
            base_cfg = {
                "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
                "objects": {
                    "mac_groups": {"clients": [client_mac]},
                },
                "pipeline": {
                    "layer_2": [{
                        "rule_id": 10,
                        "match": {"src_mac": "object:clients"},
                        "action": "allow",
                        "next_layer": "layer_3",
                    }],
                },
                "default_behavior": "allow",
            }
            gate.start(base_cfg)

            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=DST_BLOCK_IP4)
                / TCP(sport=12345, dport=9999)
            )

            # Phase 1: no dst rule → packet passes.
            assert send_and_check(pkt, f"dst host {DST_BLOCK_IP4}",
                                  expect_pass=True), \
                "no dst rule should let traffic through"

            # Phase 2: reload with a dst-drop rule → packet drops.
            gate.reload_config(_dst_only_config(veth_pair))
            assert send_and_check(pkt, f"dst host {DST_BLOCK_IP4}",
                                  expect_pass=False), \
                "dst rule installed via reload must take effect"

            # Phase 3: reload back to no-dst → packet passes again.
            # Catches the "lpm_keys_dst not cleared on shadow swap" leak.
            gate.reload_config(base_cfg)
            assert send_and_check(pkt, f"dst host {DST_BLOCK_IP4}",
                                  expect_pass=True), \
                "dst rule removed via reload must stop dropping traffic"
        finally:
            gate.stop()
