"""
AF_XDP userspace redirect functional tests.

Verifies end-to-end behavior of the userspace action:

When AF_XDP sockets bind successfully:
  - Packets with action=userspace are redirected to AF_XDP socket (not kernel stack)
  - AF_XDP callback logs received packets
  - STAT_USERSPACE Prometheus counter increments

When AF_XDP sockets are unavailable (e.g., veth on kernel < 6.3):
  - Graceful degradation: pktgate continues running
  - Userspace packets fallback to XDP_PASS (reach kernel stack)
  - Non-userspace rules (allow/drop) are unaffected

Both modes are tested. Socket-dependent tests are auto-skipped when
AF_XDP bind fails (detected from startup logs).

Requires veth pair in namespaces (provided by conftest.py session fixtures).
"""

import os
import re
import signal
import subprocess
import tempfile
import threading
import time

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, wrpcap

from conftest import (
    PktgateProcess, _run, nsexec, send_and_check, send_from_client,
    capture_on_filter, capture_count,
    NS_FILTER, NS_CLIENT, VETH_FILTER, VETH_CLIENT,
    CLIENT_IP4, FILTER_IP4, CLIENT_IP6, FILTER_IP6,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

METRICS_PORT = 19299   # Different from mirror tests to avoid conflicts


# ---------------------------------------------------------------------------
# Prometheus helpers
# ---------------------------------------------------------------------------

def scrape_metrics(port=METRICS_PORT):
    """Scrape /metrics from pktgate inside ns_ft_filter."""
    cmd = (
        f"ip netns exec {NS_FILTER} "
        f"curl -s --max-time 3 http://127.0.0.1:{port}/metrics"
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
    if r.returncode != 0:
        return {}

    metrics = {}
    for line in r.stdout.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.rsplit(None, 1)
        if len(parts) == 2:
            metrics[parts[0]] = float(parts[1])
    return metrics


def get_metric(metrics, name):
    return metrics.get(name, 0.0)


# ---------------------------------------------------------------------------
# Gate lifecycle helpers
# ---------------------------------------------------------------------------

def _start_afxdp_gate(config, metrics_port=METRICS_PORT):
    """Start pktgate with AF_XDP config + Prometheus.

    Returns (gate, afxdp_active) where afxdp_active indicates
    whether AF_XDP sockets were successfully created.
    """
    gate = PktgateProcess()
    gate.start(
        config,
        extra_args=["--metrics-port", str(metrics_port), "--afxdp-queues", "1"],
    )
    # Check stderr (non-blocking peek) for AF_XDP status
    # We can't read stderr while process is running without blocking,
    # so we'll check at stop time. Return gate and detect later.
    return gate


def _stop_and_get_stderr(gate):
    """Stop gate and return stderr as string (for log verification)."""
    stderr_text = ""
    if gate.proc and gate.proc.poll() is None:
        gate.proc.send_signal(signal.SIGTERM)
        try:
            _, stderr_bytes = gate.proc.communicate(timeout=5)
            stderr_text = stderr_bytes.decode(errors="replace")
        except subprocess.TimeoutExpired:
            gate.proc.kill()
            gate.proc.wait(timeout=2)
    # Prevent PktgateProcess.stop() from sending SIGTERM again
    gate.proc = None
    gate.stop()
    return stderr_text


def _afxdp_is_active(stderr_text):
    """Check if AF_XDP sockets were successfully created from log output."""
    return "AF_XDP userspace path active" in stderr_text


# ---------------------------------------------------------------------------
# Config builders
# ---------------------------------------------------------------------------

def _afxdp_l3_config(client_mac):
    """L3 userspace action — terminal (no L4)."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "afxdp": {"enabled": True, "queues": 1},
        "objects": {
            "subnets": {"client_net": "10.99.0.0/24"},
            "mac_groups": {"allowed_macs": [client_mac]},
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
                "description": "Redirect client subnet to userspace",
                "match": {"src_ip": "object:client_net"},
                "action": "userspace",
            }],
            "layer_4": [],
        },
        "default_behavior": "drop",
    }


def _afxdp_l4_config(client_mac):
    """L3 allows to L4, L4 has userspace action on TCP/8080."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "afxdp": {"enabled": True, "queues": 1},
        "objects": {
            "subnets": {"client_net": "10.99.0.0/24"},
            "mac_groups": {"allowed_macs": [client_mac]},
            "port_groups": {"custom": [8080]},
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
                "match": {"src_ip": "object:client_net"},
                "action": "allow",
                "next_layer": "layer_4",
            }],
            "layer_4": [{
                "rule_id": 1000,
                "description": "TCP/8080 to userspace",
                "match": {"protocol": "TCP", "dst_port": "object:custom"},
                "action": "userspace",
            }],
        },
        "default_behavior": "drop",
    }


def _afxdp_mixed_config(client_mac):
    """Mixed: TCP/80 allow (kernel), TCP/8080 userspace (AF_XDP), rest drop."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "afxdp": {"enabled": True, "queues": 1},
        "objects": {
            "subnets": {"client_net": "10.99.0.0/24"},
            "mac_groups": {"allowed_macs": [client_mac]},
            "port_groups": {"web": [80], "custom": [8080]},
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
                "match": {"src_ip": "object:client_net"},
                "action": "allow",
                "next_layer": "layer_4",
            }],
            "layer_4": [
                {
                    "rule_id": 1000,
                    "description": "TCP/80 to kernel (allow)",
                    "match": {"protocol": "TCP", "dst_port": "object:web"},
                    "action": "allow",
                },
                {
                    "rule_id": 1010,
                    "description": "TCP/8080 to userspace",
                    "match": {"protocol": "TCP", "dst_port": "object:custom"},
                    "action": "userspace",
                },
            ],
        },
        "default_behavior": "drop",
    }


def _afxdp_ipv6_config(client_mac):
    """IPv6 L3 userspace action — terminal."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "afxdp": {"enabled": True, "queues": 1},
        "objects": {
            "subnets6": {"allowed_v6": "fd00::/64"},
            "mac_groups": {"allowed_macs": [client_mac]},
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
                "description": "IPv6 client to userspace",
                "match": {"src_ip6": "object6:allowed_v6"},
                "action": "userspace",
            }],
            "layer_4": [],
        },
        "default_behavior": "drop",
    }


def _afxdp_l3_to_l4_config(client_mac):
    """L3 userspace flag propagated through L4 — tests flag-based redirect."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "afxdp": {"enabled": True, "queues": 1},
        "objects": {
            "subnets": {"client_net": "10.99.0.0/24"},
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
            "layer_3": [{
                "rule_id": 100,
                "match": {"src_ip": "object:client_net"},
                "action": "userspace",
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


# ---------------------------------------------------------------------------
# Tests: Graceful degradation (always run — no AF_XDP sockets needed)
# ---------------------------------------------------------------------------

class TestAfXdpFallback:
    """Tests that verify behavior when AF_XDP sockets are unavailable.

    On systems where AF_XDP bind fails (e.g., veth on kernel < 6.3),
    pktgate should continue running and userspace-action packets
    should fallback to XDP_PASS (delivered to kernel stack).
    """

    def test_graceful_degradation_startup(self, veth_pair):
        """pktgate must start successfully even when AF_XDP bind fails."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            assert gate.proc.poll() is None, "pktgate must be running"
            stderr = _stop_and_get_stderr(gate)
            # Should contain either "active" or "fallback" log
            assert ("AF_XDP userspace path active" in stderr or
                    "AF_XDP init failed" in stderr), \
                f"Unexpected startup log:\n{stderr[-500:]}"
        finally:
            gate.stop()

    def test_fallback_l3_userspace_passes(self, veth_pair):
        """When AF_XDP unavailable, L3 userspace packets fallback to XDP_PASS.

        bpf_redirect_map with empty xsks_map uses XDP_PASS fallback,
        so packets reach kernel stack normally.
        """
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            stderr = _stop_and_get_stderr(gate)
            if _afxdp_is_active(stderr):
                pytest.skip("AF_XDP is active — fallback test not applicable")

        finally:
            gate.stop()

        # Restart for actual packet test (previous gate was stopped for log check)
        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            # xsks_map empty → bpf_redirect_map fallback → XDP_PASS → kernel
            assert send_and_check(pkt, "tcp port 80", expect_pass=True), \
                "Without AF_XDP socket, userspace packets must fallback to kernel"
        finally:
            gate.stop()

    def test_fallback_l4_userspace_passes(self, veth_pair):
        """When AF_XDP unavailable, L4 userspace packets fallback to XDP_PASS."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l4_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            stderr = _stop_and_get_stderr(gate)
            if _afxdp_is_active(stderr):
                pytest.skip("AF_XDP is active — fallback test not applicable")
        finally:
            gate.stop()

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=8080, flags="S")
            )
            assert send_and_check(pkt, "tcp port 8080", expect_pass=True), \
                "L4 userspace packets must fallback to kernel without AF_XDP"
        finally:
            gate.stop()

    def test_fallback_ipv6_userspace_passes(self, veth_pair):
        """When AF_XDP unavailable, IPv6 userspace packets fallback to XDP_PASS."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_ipv6_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            stderr = _stop_and_get_stderr(gate)
            if _afxdp_is_active(stderr):
                pytest.skip("AF_XDP is active — fallback test not applicable")
        finally:
            gate.stop()

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
                / TCP(sport=44444, dport=80, flags="S")
            )
            assert send_and_check(pkt, "ip6 and tcp port 80", expect_pass=True), \
                "IPv6 userspace packets must fallback to kernel without AF_XDP"
        finally:
            gate.stop()

    def test_fallback_mixed_allow_unaffected(self, veth_pair):
        """Non-userspace rules work correctly alongside userspace fallback."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_mixed_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            stderr = _stop_and_get_stderr(gate)
            if _afxdp_is_active(stderr):
                pytest.skip("AF_XDP is active — fallback test not applicable")
        finally:
            gate.stop()

        gate = _start_afxdp_gate(config)
        try:
            # TCP/80 — allow → kernel (should always work)
            pkt80 = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            assert send_and_check(pkt80, "tcp port 80", expect_pass=True), \
                "TCP/80 (allow) must reach kernel"

            # TCP/8080 — userspace fallback → kernel (no AF_XDP socket)
            pkt8080 = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=8080, flags="S")
            )
            assert send_and_check(pkt8080, "tcp port 8080", expect_pass=True), \
                "TCP/8080 (userspace fallback) must reach kernel"

            # TCP/9999 — no rule, default drop
            pkt9999 = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=9999, flags="S")
            )
            assert send_and_check(pkt9999, "tcp port 9999", expect_pass=False), \
                "TCP/9999 (no rule) must be dropped"
        finally:
            gate.stop()

    def test_fallback_l3_flag_propagates_to_l4(self, veth_pair):
        """L3 userspace flag propagation works in fallback mode too."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_to_l4_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            stderr = _stop_and_get_stderr(gate)
            if _afxdp_is_active(stderr):
                pytest.skip("AF_XDP is active — fallback test not applicable")
        finally:
            gate.stop()

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            # L3 userspace + L4 allow → maybe_redirect_xsk → fallback XDP_PASS
            assert send_and_check(pkt, "tcp port 80", expect_pass=True), \
                "L3→L4 userspace flag propagation must fallback to kernel"
        finally:
            gate.stop()

    def test_fallback_stat_counter(self, veth_pair):
        """STAT_USERSPACE counter increments even in fallback mode."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            stderr = _stop_and_get_stderr(gate)
            if _afxdp_is_active(stderr):
                pytest.skip("AF_XDP is active — fallback test not applicable")
        finally:
            gate.stop()

        gate = _start_afxdp_gate(config)
        try:
            m_before = scrape_metrics()
            before_val = get_metric(m_before, 'pktgate_action_total{action="userspace"}')

            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            send_from_client(pkt, count=5)
            time.sleep(1.5)

            m_after = scrape_metrics()
            after_val = get_metric(m_after, 'pktgate_action_total{action="userspace"}')

            assert after_val > before_val, (
                f"STAT_USERSPACE must increase even in fallback: "
                f"before={before_val}, after={after_val}"
            )
        finally:
            gate.stop()


# ---------------------------------------------------------------------------
# Tests: AF_XDP socket-dependent (skipped when bind fails)
# ---------------------------------------------------------------------------

class TestAfXdpSocket:
    """Tests that require working AF_XDP sockets.

    Auto-skipped on systems where AF_XDP bind fails (e.g., veth on kernel < 6.3).
    """

    @pytest.fixture(autouse=True)
    def _check_afxdp_support(self, veth_pair):
        """Skip all tests in this class if AF_XDP sockets can't bind."""
        client_mac, _ = veth_pair
        config = _afxdp_l3_config(client_mac)
        gate = _start_afxdp_gate(config)
        stderr = _stop_and_get_stderr(gate)
        if not _afxdp_is_active(stderr):
            pytest.skip("AF_XDP bind not supported (kernel/driver limitation)")

    def test_l3_userspace_not_in_kernel(self, veth_pair):
        """Packet matching L3 userspace rule should NOT appear in tcpdump."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            assert send_and_check(pkt, "tcp port 80", expect_pass=False), \
                "Userspace-redirected packet should NOT appear on kernel stack"
        finally:
            gate.stop()

    def test_l4_userspace_not_in_kernel(self, veth_pair):
        """Packet matching L4 userspace rule (TCP/8080) should NOT appear in tcpdump."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l4_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=8080, flags="S")
            )
            assert send_and_check(pkt, "tcp port 8080", expect_pass=False), \
                "L4 userspace-redirected packet should NOT appear on kernel stack"
        finally:
            gate.stop()

    def test_mixed_allow_reaches_kernel(self, veth_pair):
        """TCP/80 (allow) reaches kernel; TCP/8080 (userspace) does not."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_mixed_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            pkt80 = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            assert send_and_check(pkt80, "tcp port 80", expect_pass=True), \
                "TCP/80 (allow) must reach kernel stack"

            pkt8080 = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=8080, flags="S")
            )
            assert send_and_check(pkt8080, "tcp port 8080", expect_pass=False), \
                "TCP/8080 (userspace) must NOT reach kernel stack"
        finally:
            gate.stop()

    def test_ipv6_userspace(self, veth_pair):
        """IPv6 packet with L3 userspace action should be redirected to AF_XDP."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_ipv6_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
                / TCP(sport=44444, dport=80, flags="S")
            )
            assert send_and_check(pkt, "ip6 and tcp port 80", expect_pass=False), \
                "IPv6 userspace packet should NOT appear on kernel stack"
        finally:
            gate.stop()

    def test_debug_log_received(self, veth_pair):
        """pktgate --debug should log 'AF_XDP: received N bytes'."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            send_from_client(pkt, count=3)
            time.sleep(1.0)

            stderr = _stop_and_get_stderr(gate)
            assert "AF_XDP: received" in stderr, (
                f"Debug log must contain 'AF_XDP: received', got:\n{stderr[-500:]}"
            )
        finally:
            gate.stop()

    def test_l3_flag_propagates_to_l4(self, veth_pair):
        """L3 userspace flag causes AF_XDP redirect even with L4 allow rule."""
        client_mac, filter_mac = veth_pair
        config = _afxdp_l3_to_l4_config(client_mac)

        gate = _start_afxdp_gate(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=44444, dport=80, flags="S")
            )
            assert send_and_check(pkt, "tcp port 80", expect_pass=False), \
                "L3 userspace flag should cause AF_XDP redirect even with L4 allow"
        finally:
            gate.stop()
