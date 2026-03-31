#!/bin/bash
set -euo pipefail

echo "=== Installing eBPF pktgate development dependencies ==="

sudo apt-get update -qq
sudo apt-get install -y \
    clang-19 llvm-19 \
    libbpf-dev \
    libelf-dev zlib1g-dev \
    bpftool \
    nlohmann-json3-dev \
    cmake g++-12 pkg-config

# Symlink bpftool if not in PATH
if ! command -v bpftool &>/dev/null; then
    sudo ln -sf /usr/sbin/bpftool /usr/local/bin/bpftool
fi

# Generate vmlinux.h if not present
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VMLINUX="${SCRIPT_DIR}/../bpf/vmlinux.h"

if [ ! -f "$VMLINUX" ]; then
    echo "=== Generating vmlinux.h ==="
    mkdir -p "$(dirname "$VMLINUX")"
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX"
fi

echo "=== Environment ready ==="
echo "Kernel:   $(uname -r)"
echo "Clang:    $(clang-19 --version 2>/dev/null || clang --version | head -1)"
echo "libbpf:   $(pkg-config --modversion libbpf)"
echo "bpftool:  $(bpftool version | head -1)"
echo "vmlinux:  $(wc -l < "$VMLINUX") lines"
