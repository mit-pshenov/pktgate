#!/usr/bin/env bash
#
# Build an RPM package for pktgate_ctl.
#
# Usage: scripts/build_rpm.sh [--mock]
#   --mock  Use mock for clean-room build (requires mock package)
#
# Without --mock: builds directly with rpmbuild on the current system.
# Output: ~/rpmbuild/RPMS/<arch>/pktgate-*.rpm
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="1.0.0"
NAME="pktgate"
TARNAME="${NAME}-${VERSION}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

command -v rpmbuild >/dev/null || err "rpmbuild not found. Install: apt install rpm (Debian) or dnf install rpm-build (Fedora)"

# ── Setup rpmbuild tree ────────────────────────────────────
TOPDIR="${HOME}/rpmbuild"
for d in BUILD BUILDROOT RPMS SOURCES SPECS SRPMS; do
    mkdir -p "${TOPDIR}/${d}"
done

# ── Create source tarball ──────────────────────────────────
info "Creating source tarball..."
SRCDIR="${TOPDIR}/SOURCES/${TARNAME}"
rm -rf "${SRCDIR}"
mkdir -p "${SRCDIR}"

# Copy project files (excluding build artifacts)
# Using tar pipe instead of rsync for portability
tar -C "${PROJECT_DIR}" \
    --exclude='./build' --exclude='./.git' --exclude='*.o' \
    -cf - . | tar -C "${SRCDIR}" -xf -

info "Source prepared in ${SRCDIR}"

# ── Copy spec ──────────────────────────────────────────────
cp "${PROJECT_DIR}/rpm/pktgate.spec" "${TOPDIR}/SPECS/pktgate.spec"

# ── Build ──────────────────────────────────────────────────
if [[ "${1:-}" == "--mock" ]]; then
    info "Building SRPM for mock..."
    rpmbuild -bs \
        --define "_topdir ${TOPDIR}" \
        "${TOPDIR}/SPECS/pktgate.spec"

    SRPM=$(ls -t "${TOPDIR}/SRPMS/${NAME}"-*.src.rpm | head -1)
    info "SRPM: ${SRPM}"
    info "Run: mock ${SRPM}"
else
    # --nodeps: skip RPM dep checks on non-RPM hosts (Debian/Ubuntu).
    # On Fedora/RHEL use mock or remove --nodeps.
    info "Building RPM with rpmbuild..."
    rpmbuild -bb \
        --nodeps \
        --define "_topdir ${TOPDIR}" \
        "${TOPDIR}/SPECS/pktgate.spec" 2>&1

    echo ""
    info "Build complete! RPMs:"
    ls -lh "${TOPDIR}/RPMS/"*/"${NAME}"-*.rpm 2>/dev/null || warn "No RPMs found"
fi
