"""
Default behavior tests — verify that default_behavior config works correctly.

Uses a separate pktgate instance with modified configs to test:
  - default_behavior: "drop" (already tested implicitly)
  - default_behavior: "allow" (new config)
  - Config hot-reload: change rules on the fly
"""

import copy
import json
import os
import time

import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw

from conftest import (
    send_and_check, CLIENT_IP4, FILTER_IP4,
    PktgateProcess,
)


class TestConfigReload:
    """Test that config hot-reload via inotify works."""

    def test_reload_adds_port(self, veth_pair, base_config):
        """Initially TCP/8080 is blocked. After reload adding port 8080, it should pass."""
        gate = PktgateProcess()
        try:
            gate.start(base_config)
            client_mac, filter_mac = veth_pair

            # TCP/8080 should be blocked initially
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=8080)
            )
            assert send_and_check(pkt, "tcp port 8080", expect_pass=False)

            # Reload config with 8080 added to web_ports
            new_config = copy.deepcopy(base_config)
            new_config["objects"]["port_groups"]["web_ports"] = [80, 443, 8080]
            gate.reload_config(new_config)

            # Now TCP/8080 should pass
            assert send_and_check(pkt, "tcp port 8080", expect_pass=True)

        finally:
            gate.stop()

    def test_reload_removes_port(self, veth_pair, base_config):
        """Remove port 443 from config. After reload, TCP/443 should be dropped."""
        gate = PktgateProcess()
        try:
            gate.start(base_config)
            client_mac, filter_mac = veth_pair

            # TCP/443 should pass initially
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=443)
            )
            assert send_and_check(pkt, "tcp port 443", expect_pass=True)

            # Reload config with 443 removed
            new_config = copy.deepcopy(base_config)
            new_config["objects"]["port_groups"]["web_ports"] = [80]
            gate.reload_config(new_config)

            # Now TCP/443 should be dropped
            assert send_and_check(pkt, "tcp port 443", expect_pass=False)

        finally:
            gate.stop()

    def test_reload_adds_mac(self, veth_pair, base_config):
        """Add a new MAC to allow-list via reload."""
        gate = PktgateProcess()
        try:
            new_mac = "de:ad:be:ef:00:42"
            gate.start(base_config)
            client_mac, filter_mac = veth_pair

            # Packets from new_mac should be blocked initially
            pkt = (
                Ether(src=new_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )
            assert send_and_check(pkt, "tcp port 80", expect_pass=False)

            # Reload with new_mac added
            new_config = copy.deepcopy(base_config)
            new_config["objects"]["mac_groups"]["allowed_macs"].append(new_mac)
            gate.reload_config(new_config)

            # Now packets from new_mac should pass
            assert send_and_check(pkt, "tcp port 80", expect_pass=True)

        finally:
            gate.stop()
