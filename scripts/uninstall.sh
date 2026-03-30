#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/pktgate}"
SYSTEMD_DIR="/etc/systemd/system"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || err "Run as root: sudo $0"

# ── Stop service ───────────────────────────────────────────────
if systemctl is-active --quiet pktgate 2>/dev/null; then
    info "Stopping pktgate service..."
    systemctl stop pktgate
fi

if systemctl is-enabled --quiet pktgate 2>/dev/null; then
    info "Disabling pktgate service..."
    systemctl disable pktgate
fi

# ── Remove files ───────────────────────────────────────────────
rm -f "$SYSTEMD_DIR/pktgate.service"
systemctl daemon-reload
info "Removed systemd unit"

rm -f "$PREFIX/bin/pktgate_ctl"
info "Removed $PREFIX/bin/pktgate_ctl"

# ── Config cleanup (ask) ──────────────────────────────────────
if [[ -d "$CONFDIR" ]]; then
    if [[ "${1:-}" == "--purge" ]]; then
        rm -rf "$CONFDIR"
        info "Purged $CONFDIR"
    else
        warn "Config dir $CONFDIR preserved (use --purge to remove)"
    fi
fi

info "Uninstall complete"
