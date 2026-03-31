"""
Mirror and redirect functional tests.

Verifies end-to-end behavior:
  - Mirror: packet cloned to mirror interface AND original continues through pipeline
  - Redirect: packet sent to redirect target, does NOT appear on filter stack
  - IPv6 variants of both
  - Prometheus metrics validation for mirror/redirect counters

Requires a third namespace (ns_ft_mirror) with a veth pair connecting
to the filter namespace.  Setup/teardown is handled by the module fixture.
"""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, wrpcap

from conftest import (
    PktgateProcess, _run, nsexec, send_and_check, send_from_client,
    NS_FILTER, NS_CLIENT, VETH_FILTER, VETH_CLIENT,
    CLIENT_IP4, FILTER_IP4, CLIENT_IP6, FILTER_IP6,
)

# ---------------------------------------------------------------------------
# Mirror namespace constants
# ---------------------------------------------------------------------------

NS_MIRROR = "ns_ft_mirror"
VETH_MIR_FLT = "veth-ft-mir"       # mirror end inside ns_ft_filter
VETH_MIR_PEER = "veth-ft-mir-p"    # peer inside ns_ft_mirror

MIRROR_IP4 = "10.88.0.1"
MIRROR_PEER_IP4 = "10.88.0.2"

METRICS_PORT = 19199   # Prometheus metrics port for functional tests


# ---------------------------------------------------------------------------
# Dummy XDP pass program for redirect targets
# ---------------------------------------------------------------------------

def _load_dummy_xdp(ns, iface):
    """Compile and load a minimal XDP_PASS program on iface inside namespace ns.

    XDP redirect to a veth requires the receiving peer to have an XDP program;
    veth_xdp_xmit() checks rcv_priv->xdp_prog and returns -ENXIO without it.
    """
    obj_path = "/tmp/xdp_pass.o"

    if not os.path.exists(obj_path):
        src = (
            'int __attribute__((section("xdp"))) xdp_pass(void *ctx) { return 2; }\n'
            'char _license[] __attribute__((section("license"))) = "GPL";\n'
        )
        src_path = "/tmp/xdp_pass.c"
        with open(src_path, "w") as f:
            f.write(src)
        for cc in ("clang-19", "clang-18", "clang-17", "clang-16", "clang"):
            if shutil.which(cc):
                _run(f"{cc} -target bpf -O2 -c {src_path} -o {obj_path}")
                break
        else:
            pytest.skip("no clang found for BPF compilation")

    nsexec(ns, f"ip link set dev {iface} xdp obj {obj_path} sec xdp")


# ---------------------------------------------------------------------------
# Mirror namespace fixture (module scope)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mirror_env(veth_pair):
    """Create a third namespace with a veth pair for mirror/redirect targets.

    Layout:
        ns_ft_filter: veth-ft-mir  (10.88.0.1/24)
           |
        ns_ft_mirror: veth-ft-mir-p (10.88.0.2/24)

    Yields (client_mac, filter_mac, mirror_ifname) where mirror_ifname
    is the interface name inside ns_ft_filter that pktgate can use as target.
    """
    client_mac, filter_mac = veth_pair

    # Clean up stale state
    _run(f"ip netns del {NS_MIRROR}", check=False)
    time.sleep(0.2)

    # Create mirror namespace
    _run(f"ip netns add {NS_MIRROR}")

    # Create veth pair
    _run(f"ip link add {VETH_MIR_FLT} type veth peer name {VETH_MIR_PEER}")

    # Move endpoints to namespaces
    _run(f"ip link set {VETH_MIR_FLT} netns {NS_FILTER}")
    _run(f"ip link set {VETH_MIR_PEER} netns {NS_MIRROR}")

    # Configure filter side (mirror target)
    nsexec(NS_FILTER, f"ip addr add {MIRROR_IP4}/24 dev {VETH_MIR_FLT}")
    nsexec(NS_FILTER, f"ip link set {VETH_MIR_FLT} up")

    # Configure mirror side (capture point)
    nsexec(NS_MIRROR, f"ip addr add {MIRROR_PEER_IP4}/24 dev {VETH_MIR_PEER}")
    nsexec(NS_MIRROR, f"ip link set {VETH_MIR_PEER} up")
    nsexec(NS_MIRROR, f"ip link set lo up")

    time.sleep(0.5)

    # XDP redirect to a veth requires an XDP program on the receiving peer.
    # veth_xdp_xmit() checks rcv_priv->xdp_prog on the peer side;
    # without it, redirected packets are silently dropped (-ENXIO).
    _load_dummy_xdp(NS_MIRROR, VETH_MIR_PEER)

    yield client_mac, filter_mac, VETH_MIR_FLT

    # Cleanup mirror infrastructure
    nsexec(NS_MIRROR, f"ip link set dev {VETH_MIR_PEER} xdp off", check=False)
    nsexec(NS_FILTER, f"ip link del {VETH_MIR_FLT}", check=False)
    _run(f"ip netns del {NS_MIRROR}", check=False)
    _run("rm -f /tmp/xdp_pass.o", check=False)


# ---------------------------------------------------------------------------
# Capture helpers
# ---------------------------------------------------------------------------

def capture_on_mirror(bpf_filter, timeout=4, count=10):
    """Capture packets on the mirror peer interface inside ns_ft_mirror."""
    cmd = (
        f"timeout {timeout} "
        f"ip netns exec {NS_MIRROR} "
        f"tcpdump -i {VETH_MIR_PEER} -c {count} -nn -l --immediate-mode "
        f"'{bpf_filter}' 2>/dev/null"
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                       timeout=timeout + 5)
    return r.stdout


def send_and_capture_both(pkt, bpf_filter, count=3, timeout=4):
    """Send packets from client, capture on both filter and mirror interfaces.

    Returns (filter_got_packets: bool, mirror_got_packets: bool).
    """
    from conftest import capture_on_filter

    pcap_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            pcap_path = f.name
            wrpcap(pcap_path, [pkt] * count)

        filter_out = []
        mirror_out = []

        def _cap_filter():
            try:
                out = capture_on_filter(bpf_filter, timeout=timeout, count=count)
                filter_out.append(out)
            except Exception:
                filter_out.append("")

        def _cap_mirror():
            try:
                out = capture_on_mirror(bpf_filter, timeout=timeout, count=count)
                mirror_out.append(out)
            except Exception:
                mirror_out.append("")

        # Start both captures
        t_flt = threading.Thread(target=_cap_filter, daemon=True)
        t_mir = threading.Thread(target=_cap_mirror, daemon=True)
        t_flt.start()
        t_mir.start()

        time.sleep(0.5)  # let tcpdump start

        # Send packets
        script = (
            f"from scapy.all import sendp, rdpcap, conf; "
            f"conf.verb = 0; "
            f"pkts = rdpcap('{pcap_path}'); "
            f"sendp(pkts, iface='{VETH_CLIENT}', verbose=0)"
        )
        nsexec(NS_CLIENT, f"python3 -c \"{script}\"", timeout=10)

        t_flt.join(timeout=timeout + 3)
        t_mir.join(timeout=timeout + 3)

        flt_got = bool((filter_out[0] if filter_out else "").strip())
        mir_got = bool((mirror_out[0] if mirror_out else "").strip())
        return flt_got, mir_got

    finally:
        if pcap_path:
            os.unlink(pcap_path)


# ---------------------------------------------------------------------------
# Prometheus metrics helpers
# ---------------------------------------------------------------------------

def scrape_metrics(port=METRICS_PORT):
    """Scrape /metrics from pktgate Prometheus exporter inside ns_ft_filter.

    Returns dict of metric_name → float value.
    """
    # pktgate listens on 0.0.0.0 inside the namespace;
    # we curl from inside the namespace to reach it.
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
    """Get a metric value by name, return 0 if not found."""
    return metrics.get(name, 0.0)


# ---------------------------------------------------------------------------
# Config builders
# ---------------------------------------------------------------------------

def _mirror_config(client_mac, mirror_iface):
    """Config with L3 mirror rule: mirror client subnet to mirror_iface, then L4."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
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
                "description": "Mirror client subnet",
                "match": {"src_ip": "object:client_net"},
                "action": "mirror",
                "action_params": {"target_port": mirror_iface},
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


def _mirror_v6_config(client_mac, mirror_iface):
    """Config with IPv6 L3 mirror rule."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "objects": {
            "subnets6": {"client_v6": "fd00::/64"},
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
                "description": "Mirror IPv6 client subnet",
                "match": {"src_ip6": "object6:client_v6"},
                "action": "mirror",
                "action_params": {"target_port": mirror_iface},
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


def _redirect_config(client_mac, redirect_iface):
    """Config with L3 redirect rule: redirect client subnet to another interface."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
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
                "description": "Redirect client subnet",
                "match": {"src_ip": "object:client_net"},
                "action": "redirect",
                "action_params": {"target_vrf": redirect_iface},
            }],
        },
        "default_behavior": "drop",
    }


def _redirect_v6_config(client_mac, redirect_iface):
    """Config with IPv6 L3 redirect rule."""
    return {
        "device_info": {"interface": VETH_FILTER, "capacity": "1Gbps"},
        "objects": {
            "subnets6": {"client_v6": "fd00::/64"},
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
                "description": "Redirect IPv6 client subnet",
                "match": {"src_ip6": "object6:client_v6"},
                "action": "redirect",
                "action_params": {"target_vrf": redirect_iface},
            }],
        },
        "default_behavior": "drop",
    }


# ---------------------------------------------------------------------------
# Helper: start gate with --metrics-port
# ---------------------------------------------------------------------------

def _start_gate_with_metrics(config):
    """Start PktgateProcess with Prometheus metrics enabled."""
    gate = PktgateProcess()
    gate.start(config, extra_args=["--metrics-port", str(METRICS_PORT)])
    return gate


# ===========================================================================
# Mirror tests
# ===========================================================================

class TestMirrorIPv4:
    """Mirror action: packet cloned to mirror interface, original continues."""

    def test_mirror_clone_arrives(self, mirror_env):
        """Mirrored packet clone should arrive at the mirror peer interface."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _mirror_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )

            flt_got, mir_got = send_and_capture_both(pkt, "tcp port 80")
            assert flt_got, "Original packet should pass through pipeline"
            assert mir_got, "Clone should arrive at mirror interface"
        finally:
            gate.stop()

    def test_mirror_original_passes_l4(self, mirror_env):
        """Original packet should continue to L4 after mirror at L3."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _mirror_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            # TCP/80 is allowed in L4 → should pass
            pkt_allow = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )
            assert send_and_check(pkt_allow, "tcp port 80", expect_pass=True)

            # TCP/9999 is NOT in L4 rules → should be dropped by default
            pkt_drop = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9999)
            )
            assert send_and_check(pkt_drop, "tcp port 9999", expect_pass=False)
        finally:
            gate.stop()

    def test_mirror_clone_of_dropped_packet(self, mirror_env):
        """If L4 drops (XDP_DROP), TC never runs → no mirror clone."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _mirror_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            # TCP/9999 will be dropped at L4 (XDP_DROP before TC)
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=9999)
            )

            flt_got, mir_got = send_and_capture_both(pkt, "tcp port 9999")
            assert not flt_got, "Packet dropped at L4 should not appear on filter"
            assert not mir_got, "Clone should not happen when L4 drops (XDP_DROP before TC)"
        finally:
            gate.stop()


class TestMirrorIPv6:
    """Mirror action with IPv6 traffic."""

    def test_mirror_v6_clone_arrives(self, mirror_env):
        """IPv6 mirrored packet clone should arrive at mirror peer."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _mirror_v6_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
                / TCP(sport=12345, dport=80)
            )

            flt_got, mir_got = send_and_capture_both(pkt, "tcp port 80")
            assert flt_got, "Original IPv6 packet should pass"
            assert mir_got, "IPv6 clone should arrive at mirror interface"
        finally:
            gate.stop()


# ===========================================================================
# Redirect tests
# ===========================================================================

class TestRedirectIPv4:
    """Redirect action: packet sent to target interface via XDP_REDIRECT."""

    def test_redirect_arrives_at_target(self, mirror_env):
        """Redirected packet should appear on the redirect target peer."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _redirect_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )

            # Capture on mirror peer — redirect target
            mir_out = []

            def _cap():
                try:
                    out = capture_on_mirror("tcp port 80", timeout=4, count=3)
                    mir_out.append(out)
                except Exception:
                    mir_out.append("")

            t = threading.Thread(target=_cap, daemon=True)
            t.start()
            time.sleep(0.5)

            send_from_client(pkt, count=3)

            t.join(timeout=7)
            got = bool((mir_out[0] if mir_out else "").strip())
            assert got, "Redirected packet should arrive at target peer"
        finally:
            gate.stop()

    def test_redirect_not_on_filter(self, mirror_env):
        """Redirected packet should NOT appear on the filter's own stack."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _redirect_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )

            assert send_and_check(pkt, "tcp port 80", expect_pass=False), \
                "Redirected packet should not appear on filter interface"
        finally:
            gate.stop()


class TestRedirectIPv6:
    """Redirect action with IPv6 traffic."""

    def test_redirect_v6_arrives_at_target(self, mirror_env):
        """IPv6 redirected packet should appear on target peer."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _redirect_v6_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
                / TCP(sport=12345, dport=80)
            )

            mir_out = []

            def _cap():
                try:
                    out = capture_on_mirror("tcp port 80", timeout=4, count=3)
                    mir_out.append(out)
                except Exception:
                    mir_out.append("")

            t = threading.Thread(target=_cap, daemon=True)
            t.start()
            time.sleep(0.5)

            send_from_client(pkt, count=3)

            t.join(timeout=7)
            got = bool((mir_out[0] if mir_out else "").strip())
            assert got, "IPv6 redirected packet should arrive at target peer"
        finally:
            gate.stop()

    def test_redirect_v6_not_on_filter(self, mirror_env):
        """IPv6 redirected packet should NOT appear on filter stack."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _redirect_v6_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IPv6(src=CLIENT_IP6, dst=FILTER_IP6)
                / TCP(sport=12345, dport=80)
            )

            assert send_and_check(pkt, "tcp port 80", expect_pass=False), \
                "IPv6 redirected packet should not appear on filter"
        finally:
            gate.stop()


# ===========================================================================
# Prometheus metrics validation
# ===========================================================================

class TestMirrorMetrics:
    """Verify Prometheus counters for mirror actions."""

    def test_mirror_metrics_increment(self, mirror_env):
        """After mirroring, pktgate_action_total{action=mirror} and
        pktgate_tc_total{action=mirror} should be > 0."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _mirror_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )

            # Send several packets to ensure counters increment
            send_and_capture_both(pkt, "tcp port 80", count=5, timeout=5)

            # Small delay for counters to settle
            time.sleep(0.5)

            m = scrape_metrics()
            assert m, "Prometheus /metrics should be reachable"

            # XDP layer sets mirror flag
            mirror_xdp = get_metric(m, 'pktgate_action_total{action="mirror"}')
            assert mirror_xdp >= 5, \
                f"pktgate_action_total{{action=mirror}} = {mirror_xdp}, expected >= 5"

            # TC performs the actual clone
            mirror_tc = get_metric(m, 'pktgate_tc_total{action="mirror"}')
            assert mirror_tc >= 5, \
                f"pktgate_tc_total{{action=mirror}} = {mirror_tc}, expected >= 5"

            # Packets total should be > 0
            total = get_metric(m, "pktgate_packets_total")
            assert total >= 5, f"pktgate_packets_total = {total}, expected >= 5"

            # L4 pass (TCP/80 allowed)
            l4_pass = get_metric(m, 'pktgate_pass_total{layer="l4"}')
            assert l4_pass >= 5, \
                f"pktgate_pass_total{{layer=l4}} = {l4_pass}, expected >= 5"
        finally:
            gate.stop()


class TestRedirectMetrics:
    """Verify Prometheus counters for redirect actions."""

    def test_redirect_metrics_increment(self, mirror_env):
        """After redirecting, pktgate_action_total{action=redirect} should be > 0."""
        client_mac, filter_mac, mir_iface = mirror_env
        config = _redirect_config(client_mac, mir_iface)
        gate = _start_gate_with_metrics(config)
        try:
            pkt = (
                Ether(src=client_mac, dst=filter_mac)
                / IP(src=CLIENT_IP4, dst=FILTER_IP4)
                / TCP(sport=12345, dport=80)
            )

            # Send packets (capture on mirror side to give them time)
            mir_out = []

            def _cap():
                try:
                    out = capture_on_mirror("tcp port 80", timeout=5, count=5)
                    mir_out.append(out)
                except Exception:
                    mir_out.append("")

            t = threading.Thread(target=_cap, daemon=True)
            t.start()
            time.sleep(0.5)

            send_from_client(pkt, count=5)
            t.join(timeout=8)

            time.sleep(0.5)

            m = scrape_metrics()
            assert m, "Prometheus /metrics should be reachable"

            redirect_cnt = get_metric(m, 'pktgate_action_total{action="redirect"}')
            assert redirect_cnt >= 5, \
                f"pktgate_action_total{{action=redirect}} = {redirect_cnt}, expected >= 5"

            total = get_metric(m, "pktgate_packets_total")
            assert total >= 5, f"pktgate_packets_total = {total}, expected >= 5"

            # No TC mirror should happen for redirect
            tc_mirror = get_metric(m, 'pktgate_tc_total{action="mirror"}')
            assert tc_mirror == 0, \
                f"pktgate_tc_total{{action=mirror}} should be 0 for redirect, got {tc_mirror}"
        finally:
            gate.stop()
