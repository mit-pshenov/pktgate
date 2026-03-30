"""
Functional test infrastructure for pktgate XDP filter.

Fixtures handle:
  - veth pair creation in network namespaces
  - MAC address discovery
  - pktgate process lifecycle
  - JSON config generation
  - Packet send/receive helpers via scapy
"""

import json
import os
import re
import signal
import subprocess
import tempfile
import time

import pytest
from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
    Raw, sendp, sniff, conf, get_if_hwaddr,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKTGATE_BIN = os.path.join(PROJECT_ROOT, "build", "pktgate_ctl")

NS_FILTER = "ns_ft_filter"
NS_CLIENT = "ns_ft_client"
VETH_FILTER = "veth-ft-flt"
VETH_CLIENT = "veth-ft-cli"

FILTER_IP4 = "10.99.0.1"
CLIENT_IP4 = "10.99.0.2"
BLOCKED_IP4 = "10.99.0.99"

FILTER_IP6 = "fd00::1"
CLIENT_IP6 = "fd00::2"
BLOCKED_IP6 = "fd00:dead::1"

FILTER_NET4 = "10.99.0.0/24"
CLIENT_NET4 = "10.99.0.0/24"
BLOCKED_NET4 = "10.99.0.99/32"

FILTER_NET6 = "fd00::/64"
BLOCKED_NET6 = "fd00:dead::/48"

# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------


def _run(cmd, check=True, timeout=10):
    """Run shell command, return stdout."""
    r = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout,
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nstderr: {r.stderr}")
    return r.stdout.strip()


def nsexec(ns, cmd, **kw):
    """Run command inside a network namespace."""
    return _run(f"ip netns exec {ns} {cmd}", **kw)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def veth_pair():
    """Create veth pair in namespaces. Yields (client_mac, filter_mac). Cleans up on exit."""

    # Ensure clean state
    _run(f"ip netns del {NS_FILTER}", check=False)
    _run(f"ip netns del {NS_CLIENT}", check=False)
    time.sleep(0.2)

    # Create namespaces
    _run(f"ip netns add {NS_FILTER}")
    _run(f"ip netns add {NS_CLIENT}")

    # Create veth pair
    _run(f"ip link add {VETH_FILTER} type veth peer name {VETH_CLIENT}")

    # Move to namespaces
    _run(f"ip link set {VETH_FILTER} netns {NS_FILTER}")
    _run(f"ip link set {VETH_CLIENT} netns {NS_CLIENT}")

    # Configure filter side
    nsexec(NS_FILTER, f"ip addr add {FILTER_IP4}/24 dev {VETH_FILTER}")
    nsexec(NS_FILTER, f"ip -6 addr add {FILTER_IP6}/64 dev {VETH_FILTER}")
    nsexec(NS_FILTER, f"ip link set {VETH_FILTER} up")
    nsexec(NS_FILTER, f"ip link set lo up")

    # Configure client side
    nsexec(NS_CLIENT, f"ip addr add {CLIENT_IP4}/24 dev {VETH_CLIENT}")
    nsexec(NS_CLIENT, f"ip -6 addr add {CLIENT_IP6}/64 dev {VETH_CLIENT}")
    nsexec(NS_CLIENT, f"ip link set {VETH_CLIENT} up")
    nsexec(NS_CLIENT, f"ip link set lo up")

    # Discover MAC addresses
    filter_mac = _get_mac(NS_FILTER, VETH_FILTER)
    client_mac = _get_mac(NS_CLIENT, VETH_CLIENT)

    # Wait for link to settle
    time.sleep(0.5)

    yield client_mac, filter_mac

    # Cleanup
    _run(f"ip netns del {NS_FILTER}", check=False)
    _run(f"ip netns del {NS_CLIENT}", check=False)


def _get_mac(ns, iface):
    """Get MAC address of interface in namespace."""
    out = nsexec(ns, f"ip link show {iface}")
    m = re.search(r"link/ether\s+([\da-f:]+)", out)
    if not m:
        raise RuntimeError(f"Cannot find MAC for {iface} in {ns}")
    return m.group(1)


@pytest.fixture(scope="session")
def base_config(veth_pair):
    """
    Return a dict config that exercises all layers:
      L2: allow client MAC only
      L3: drop BLOCKED_IP4, allow CLIENT_NET4 → L4; drop BLOCKED_IP6, allow FILTER_NET6 → L4
      L4: allow TCP/80,443; allow UDP/53 (tag EF); drop everything else
      Default: drop
    """
    client_mac, filter_mac = veth_pair

    return {
        "device_info": {
            "interface": VETH_FILTER,
            "capacity": "1Gbps",
        },
        "objects": {
            "subnets": {
                "client_net": CLIENT_NET4,
                "blocked_host": BLOCKED_NET4,
            },
            "subnets6": {
                "allowed_v6": FILTER_NET6,
                "blocked_v6": BLOCKED_NET6,
            },
            "mac_groups": {
                "allowed_macs": [client_mac],
            },
            "port_groups": {
                "web_ports": [80, 443],
                "dns_ports": [53],
            },
        },
        "pipeline": {
            "layer_2": [
                {
                    "rule_id": 10,
                    "description": "Allow known client MAC",
                    "match": {"src_mac": "object:allowed_macs"},
                    "action": "allow",
                    "next_layer": "layer_3",
                },
            ],
            "layer_3": [
                {
                    "rule_id": 100,
                    "description": "Drop blocked host",
                    "match": {"src_ip": "object:blocked_host"},
                    "action": "drop",
                },
                {
                    "rule_id": 110,
                    "description": "Allow client subnet to L4",
                    "match": {"src_ip": "object:client_net"},
                    "action": "allow",
                    "next_layer": "layer_4",
                },
                {
                    "rule_id": 120,
                    "description": "Drop blocked IPv6",
                    "match": {"src_ip6": "object6:blocked_v6"},
                    "action": "drop",
                },
                {
                    "rule_id": 130,
                    "description": "Allow IPv6 clients to L4",
                    "match": {"src_ip6": "object6:allowed_v6"},
                    "action": "allow",
                    "next_layer": "layer_4",
                },
            ],
            "layer_4": [
                {
                    "rule_id": 1000,
                    "description": "Allow web traffic",
                    "match": {"protocol": "TCP", "dst_port": "object:web_ports"},
                    "action": "allow",
                },
                {
                    "rule_id": 1010,
                    "description": "Tag DNS with DSCP EF",
                    "match": {"protocol": "UDP", "dst_port": "object:dns_ports"},
                    "action": "tag",
                    "action_params": {"dscp": "EF", "cos": 5},
                },
            ],
        },
        "default_behavior": "drop",
    }


class PktgateProcess:
    """Manages a pktgate_ctl process inside the filter namespace."""

    def __init__(self):
        self.proc = None
        self.config_path = None
        self._tmpdir = None

    def start(self, config_dict, extra_args=None):
        """Write config to temp file, launch pktgate_ctl in filter namespace."""
        self.stop()

        self._tmpdir = tempfile.mkdtemp(prefix="pktgate_ft_")
        self.config_path = os.path.join(self._tmpdir, "config.json")
        with open(self.config_path, "w") as f:
            json.dump(config_dict, f, indent=2)

        cmd = ["ip", "netns", "exec", NS_FILTER, PKTGATE_BIN, "--debug"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(self.config_path)

        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Give it time to load BPF + attach XDP
        time.sleep(1.5)

        if self.proc.poll() is not None:
            stderr = self.proc.stderr.read().decode(errors="replace")
            raise RuntimeError(f"pktgate_ctl exited early (rc={self.proc.returncode}): {stderr}")

    def reload_config(self, config_dict):
        """Write new config and trigger reload via file change (inotify)."""
        with open(self.config_path, "w") as f:
            json.dump(config_dict, f, indent=2)
        # inotify picks up the write; wait for reload
        time.sleep(1.0)

    def get_stats(self):
        """Send SIGUSR1 and capture stats from stderr."""
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGUSR1)
            time.sleep(0.3)

    def stop(self):
        """Gracefully stop pktgate_ctl."""
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        self.proc = None

        if self._tmpdir:
            import shutil
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None


@pytest.fixture(scope="session")
def pktgate(veth_pair, base_config):
    """Start pktgate with base config. Shared across entire test session.

    WARNING: tests that start their own PktgateProcess (e.g., test_default.py)
    will detach XDP from the interface. They must restart pktgate afterwards
    or run after all tests that depend on this fixture.
    """
    gate = PktgateProcess()
    gate.start(base_config)
    yield gate
    gate.stop()


@pytest.fixture()
def standalone_gate():
    """Create a standalone PktgateProcess for tests that need their own instance.

    Caller is responsible for calling start() and stop().
    Cleanup is automatic on fixture teardown.
    """
    gate = PktgateProcess()
    yield gate
    gate.stop()


# ---------------------------------------------------------------------------
# Packet send/receive helpers
# ---------------------------------------------------------------------------


def send_from_client(pkt, count=1, iface=VETH_CLIENT):
    """Send a scapy packet from the client namespace.

    We write a small Python one-liner that runs inside ns_client via nsenter.
    This ensures the packet originates from the correct namespace.
    """
    from scapy.utils import wrpcap
    import tempfile

    # Write packet to pcap, then replay with tcpreplay or scapy in namespace
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name
        wrpcap(pcap_path, [pkt] * count)

    try:
        # Use scapy's sendp inside the namespace via a helper script
        script = (
            f"from scapy.all import sendp, rdpcap, conf; "
            f"conf.verb = 0; "
            f"pkts = rdpcap('{pcap_path}'); "
            f"sendp(pkts, iface='{iface}', verbose=0)"
        )
        nsexec(NS_CLIENT, f"python3 -c \"{script}\"", timeout=10)
    finally:
        os.unlink(pcap_path)


def capture_on_filter(bpf_filter, timeout=3, count=10, iface=VETH_FILTER):
    """Capture packets arriving on the filter interface (after XDP).

    Packets that pass XDP are visible to tcpdump inside the namespace.
    Packets dropped by XDP never reach here.
    """
    cmd = (
        f"timeout {timeout} "
        f"ip netns exec {NS_FILTER} "
        f"tcpdump -i {iface} -c {count} -nn -l --immediate-mode "
        f"'{bpf_filter}' 2>/dev/null"
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 5)
    return r.stdout


def send_and_check(pkt, bpf_filter, expect_pass, count=3, timeout=3):
    """Send packets from client, check if they arrive at the filter interface.

    Args:
        pkt: scapy packet to send (L2 frame)
        bpf_filter: tcpdump filter for the expected packet
        expect_pass: True if packet should pass XDP, False if should be dropped
        count: number of packets to send
        timeout: capture timeout in seconds

    Returns:
        True if result matches expectation
    """
    from scapy.utils import wrpcap
    import tempfile
    import threading

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name
        wrpcap(pcap_path, [pkt] * count)

    captured_lines = []

    def _capture():
        try:
            out = capture_on_filter(bpf_filter, timeout=timeout, count=count)
            captured_lines.append(out)
        except Exception:
            captured_lines.append("")

    # Start capture first, then send
    cap_thread = threading.Thread(target=_capture, daemon=True)
    cap_thread.start()

    # Small delay to let tcpdump start
    time.sleep(0.5)

    try:
        script = (
            f"from scapy.all import sendp, rdpcap, conf; "
            f"conf.verb = 0; "
            f"pkts = rdpcap('{pcap_path}'); "
            f"sendp(pkts, iface='{VETH_CLIENT}', verbose=0)"
        )
        nsexec(NS_CLIENT, f"python3 -c \"{script}\"", timeout=10)
    finally:
        os.unlink(pcap_path)

    cap_thread.join(timeout=timeout + 3)

    output = captured_lines[0] if captured_lines else ""
    got_packets = bool(output.strip())

    if expect_pass:
        return got_packets
    else:
        return not got_packets


def make_eth(src_mac, dst_mac):
    """Create Ethernet header with given MACs."""
    return Ether(src=src_mac, dst=dst_mac)


def capture_count(bpf_filter, timeout=3, iface=VETH_FILTER):
    """Capture packets and return how many matched the filter.

    Uses tcpdump's summary line: "N packets captured".
    """
    cmd = (
        f"timeout {timeout} "
        f"ip netns exec {NS_FILTER} "
        f"tcpdump -i {iface} -nn --immediate-mode "
        f"'{bpf_filter}' 2>&1"
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 5)
    # tcpdump prints "N packets captured" to stderr
    combined = r.stdout + r.stderr
    m = re.search(r"(\d+) packets? captured", combined)
    return int(m.group(1)) if m else 0


def capture_tos(bpf_filter, timeout=3, iface=VETH_FILTER):
    """Capture packets and extract TOS byte values from verbose tcpdump output.

    Returns list of TOS hex values (e.g., ["0xb8", "0x00"]).
    """
    cmd = (
        f"timeout {timeout} "
        f"ip netns exec {NS_FILTER} "
        f"tcpdump -i {iface} -v -nn --immediate-mode "
        f"'{bpf_filter}' 2>/dev/null"
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 5)
    return re.findall(r"tos (0x[0-9a-f]+)", r.stdout)


def send_burst(pkt, count, iface=VETH_CLIENT):
    """Send a burst of packets from client namespace. Does not capture."""
    from scapy.utils import wrpcap

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name
        wrpcap(pcap_path, [pkt] * count)

    try:
        script = (
            f"from scapy.all import sendp, rdpcap, conf; "
            f"conf.verb = 0; "
            f"pkts = rdpcap('{pcap_path}'); "
            f"sendp(pkts, iface='{iface}', verbose=0)"
        )
        nsexec(NS_CLIENT, f"python3 -c \"{script}\"", timeout=30)
    finally:
        os.unlink(pcap_path)
