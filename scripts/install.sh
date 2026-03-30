#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/pktgate}"
SYSTEMD_DIR="/etc/systemd/system"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

[[ $(id -u) -eq 0 ]] || err "Run as root: sudo $0"

# ── Build ──────────────────────────────────────────────────────
info "Building pktgate_ctl (Release)..."
cmake -B "$PROJECT_DIR/build" -S "$PROJECT_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    2>&1 | tail -3
make -C "$PROJECT_DIR/build" -j"$(nproc)" pktgate_ctl 2>&1 | tail -5
info "Build complete"

# ── Install binary ─────────────────────────────────────────────
install -Dm755 "$PROJECT_DIR/build/pktgate_ctl" "$PREFIX/bin/pktgate_ctl"
info "Installed $PREFIX/bin/pktgate_ctl"

# ── Install config ─────────────────────────────────────────────
install -dm755 "$CONFDIR"
if [[ ! -f "$CONFDIR/config.json" ]]; then
    if [[ -f "$PROJECT_DIR/sample2.json" ]]; then
        install -Dm644 "$PROJECT_DIR/sample2.json" "$CONFDIR/config.json"
        info "Installed sample config → $CONFDIR/config.json"
    else
        warn "No sample config found — create $CONFDIR/config.json manually"
    fi
else
    warn "$CONFDIR/config.json already exists — not overwriting"
fi

install -Dm644 "$PROJECT_DIR/systemd/pktgate.conf" "$CONFDIR/pktgate.conf"
info "Installed $CONFDIR/pktgate.conf (env overrides)"

# ── Install systemd unit ───────────────────────────────────────
install -Dm644 "$PROJECT_DIR/systemd/pktgate.service" "$SYSTEMD_DIR/pktgate.service"
systemctl daemon-reload
info "Installed $SYSTEMD_DIR/pktgate.service"

# ── Done ───────────────────────────────────────────────────────
echo ""
info "Installation complete! Next steps:"
echo "  1. Edit config:     vi $CONFDIR/config.json"
echo "  2. Start service:   systemctl start pktgate"
echo "  3. Enable on boot:  systemctl enable pktgate"
echo "  4. Check status:    systemctl status pktgate"
echo "  5. View logs:       journalctl -u pktgate -f"
echo "  6. Reload config:   systemctl reload pktgate"
echo "  7. Dump stats:      kill -USR1 \$(pidof pktgate_ctl)"
