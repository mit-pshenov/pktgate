%define _name   pktgate
%define _ver    1.0.0

Name:           %{_name}
Version:        %{_ver}
Release:        1%{?dist}
Summary:        High-performance eBPF/XDP packet filter with atomic config reload

License:        GPL-2.0-only
URL:            https://github.com/example/pktgate

BuildRequires:  cmake >= 3.25
BuildRequires:  gcc-c++
BuildRequires:  clang >= 16
BuildRequires:  llvm
BuildRequires:  libbpf-devel >= 1.1
BuildRequires:  bpftool
BuildRequires:  kernel-headers
BuildRequires:  elfutils-libelf-devel
BuildRequires:  zlib-devel
BuildRequires:  nlohmann-json-devel >= 3.11
# On Fedora/RHEL: BuildRequires: systemd-rpm-macros
# Omitted for cross-distro portability; systemd paths hardcoded below

Requires:       libbpf >= 1.1
Requires:       elfutils-libelf
Requires:       zlib

%description
eBPF/XDP packet filter with a JSON-driven pipeline:
  - Layer 2 (MAC), Layer 3 (IPv4/IPv6 LPM, VRF), Layer 4 (port/proto)
  - Actions: allow, drop, mirror, redirect, tag (DSCP/CoS), rate-limit
  - Atomic generation swap (zero packet loss during config updates)
  - Hot reload via SIGHUP / inotify
  - Dual-stack IPv4 + IPv6 support

%prep
# Source is injected by the build script — no tarball extraction needed
%setup -q -T -c
cp -a %{_sourcedir}/%{_name}-%{_ver}/* .

%build
mkdir -p build && cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=%{_prefix} \
    -DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir}
%{__make} %{?_smp_mflags}

%install
cd build
%{__make} install DESTDIR=%{buildroot}

# Systemd unit (cmake install already puts it in lib/systemd/system,
# but we also ensure it's there via explicit install for RPM layout)
install -Dm644 ../systemd/pktgate.service %{buildroot}/usr/lib/systemd/system/pktgate.service

# Default config (cmake install already handles this, but ensure RPM owns it)
install -Dm644 ../sample2.json %{buildroot}%{_sysconfdir}/pktgate/config.json

# Environment file
install -Dm644 ../systemd/pktgate.conf %{buildroot}%{_sysconfdir}/pktgate/pktgate.conf

%check
cd build
ctest --output-on-failure --exclude-regex 'bpf_dataplane'

%post
if [ $1 -eq 1 ] ; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ $1 -eq 0 ] ; then
    systemctl stop pktgate.service >/dev/null 2>&1 || :
    systemctl disable pktgate.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    systemctl try-restart pktgate.service >/dev/null 2>&1 || :
fi

%files
%license bpf/entry.bpf.c
%{_bindir}/pktgate_ctl
/usr/lib/systemd/system/pktgate.service
%config(noreplace) %{_sysconfdir}/pktgate/config.json
%config(noreplace) %{_sysconfdir}/pktgate/pktgate.conf

%changelog
* Mon Mar 30 2026 Filter Maintainers <noreply@example.com> - 1.0.0-1
- Initial RPM release
- Phases 1-17: full pipeline, 500+ tests (unit/integration/BPF/functional/fuzz)
- IPv6 dual-stack, systemd, hot reload, mirror/redirect, Prometheus metrics
- CI: fuzz smoke on PR, overnight fuzzing with corpus caching
