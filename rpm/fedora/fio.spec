Name:		fio
Version:	3.41
Release:	31.hipfile%{?dist}
Summary:	Multithreaded IO generation tool

License:	GPL-2.0-only
URL:		http://git.kernel.dk/?p=fio.git;a=summary
Source0:	http://brick.kernel.dk/snaps/%{name}-%{version}.tar.bz2
# hipFile: The signatures won't match as we have modified the package ourselves.
# Source1:	https://brick.kernel.dk/snaps/%{name}-%{version}.tar.bz2.asc
# Source2:	https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git/plain/keys/F7D358FB2971E0A6.asc

%if 0%{?rhel} && 0%{?rhel} < 10
%bcond_without nbd
%ifarch x86_64 ppc64le
%bcond_without pmem
%endif
%ifnarch %{arm} %{ix86}
%bcond_without rbd
%bcond_without rados
%endif
%bcond_with tcmalloc
%else
%bcond nbd 1
%ifarch x86_64 ppc64le
%bcond pmem %{undefined rhel}
%endif
%ifnarch %{arm} %{ix86}
%bcond rbd 1
%bcond rados 1
%endif
# set to %%{undefined rhel} if enabling for Fedora
%bcond tcmalloc 0
%endif

%bcond_with xnvme
%bcond_with cuda
# hipFile: Add packaging arg for the hipFile IO engine.
%bcond_with hipfile

BuildRequires:	gcc
BuildRequires:	gnupg2
BuildRequires:	libaio-devel
BuildRequires:	zlib-devel
BuildRequires:	python3-devel
%if %{with nbd}
BuildRequires:	libnbd-devel
%endif
BuildRequires:	libcurl-devel
BuildRequires:	openssl-devel
%if %{with pmem}
BuildRequires:	libpmem-devel
%endif

%if %{with rbd}
BuildRequires:	librbd1-devel
%endif

%if %{with tcmalloc}
BuildRequires:	gperftools-devel
%endif

%if %{with xnvme}
BuildRequires:	xnvme-devel
%endif

%if %{with cuda}
BuildRequires:	libcufile.so.0()(64bit)
%endif

%if %{with hipfile}
BuildRequires: hipfile-devel
%endif

%ifnarch %{arm}
BuildRequires:	numactl-devel
BuildRequires:	librdmacm-devel
BuildRequires:  libnl3-devel
%endif
BuildRequires: make

# Don't create automated dependencies for the fio engines.
# https://bugzilla.redhat.com/show_bug.cgi?id=1884954
%global __provides_exclude_from ^%{_libdir}/fio/

# Main fio package has soft dependencies on all the engine
# subpackages, but allows the engines to be uninstalled if not needed
# or if the dependencies are too onerous.
Recommends:     %{name}-engine-libaio
Recommends:     %{name}-engine-http
%if %{with nbd}
Recommends:     %{name}-engine-nbd
%endif
%if %{with pmem}
Recommends:     %{name}-engine-dev-dax
Recommends:     %{name}-engine-libpmem
%endif
%if %{with rados}
Recommends:     %{name}-engine-rados
%endif
%if %{with rbd}
Recommends:     %{name}-engine-rbd
%endif
%if %{with xnvme}
Recommends:     %{name}-engine-xnvme
%endif
%if %{with cuda}
Recommends:     %{name}-engine-cuda
%endif
%if %{with hipfile}
Recommends:     %{name}-engine-hipfile
%endif
%ifnarch %{arm}
Recommends:     %{name}-engine-rdma
%endif

%description
fio is an I/O tool that will spawn a number of threads or processes doing
a particular type of io action as specified by the user.  fio takes a
number of global parameters, each inherited by the thread unless
otherwise parameters given to them overriding that setting is given.
The typical use of fio is to write a job file matching the io load
one wants to simulate.

%package engine-libaio
Summary:        Linux libaio engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-libaio
Linux libaio engine for %{name}.

%package engine-http
Summary:        HTTP engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-http
HTTP engine for %{name}.

%if %{with nbd}
%package engine-nbd
Summary:        Network Block Device engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-nbd
Network Block Device (NBD) engine for %{name}.
%endif

%if %{with pmem}
%package engine-dev-dax
Summary:        PMDK dev-dax engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-dev-dax
dev-dax engine for %{name}.
Read and write using device DAX to a persistent memory device
(e.g., /dev/dax0.0) through the PMDK libpmem library.
%endif

%if %{with pmem}
%package engine-libpmem
Summary:        PMDK pmemblk engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-libpmem
libpmem engine for %{name}.
Read and write using mmap I/O to a file on a filesystem mounted with DAX
on a persistent memory device through the PMDK libpmem library.
%endif

%if %{with rados}
%package engine-rados
Summary:        Rados engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-rados
Rados engine for %{name}.
%endif

%if %{with rbd}
%package engine-rbd
Summary:        Rados Block Device engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-rbd
Rados Block Device (RBD) engine for %{name}.
%endif

%if %{with xnvme}
%package engine-xnvme
Summary:        XNVME engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-xnvme
XNVME engine for %{name}.
%endif

%if %{with cuda}
%package engine-cuda
Summary:        cuda engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-cuda
cuda engine for %{name}.
%endif

%if %{with hipfile}
%package engine-hipfile
Summary: ROCm hipFile engine for %{name}.
Requires: %{name}%{?_isa} = %{version}-%{release}

%description engine-hipfile
ROCm hipFile engine for %{name}.
%endif

%ifnarch %{arm}
%package engine-rdma
Summary:        RDMA engine for %{name}.
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description engine-rdma
RDMA engine for %{name}.
%endif

%prep
%autosetup -p1
# hipFile: These signatures are valid only for the original source.
#          Our modifications will cause this check to fail.
# %{gpgverify} --keyring='%{SOURCE2}' --signature='%{SOURCE1}' --data='%{SOURCE0}'

%{__python3} %{_rpmconfigdir}/redhat/pathfix.py -i %{__python3} -pn \
 tools/fio_jsonplus_clat2csv \
 tools/fiologparser.py \
 tools/hist/*.py \
 tools/plot/fio2gnuplot \
 t/steadystate_tests.py

# Edit /usr/local/lib path in os/os-linux.h to match Fedora conventions.
sed -e 's,/usr/local/lib/,%{_libdir}/,g' -i os/os-linux.h

%build

%if %{with cuda}
export C_INCLUDE_PATH=/usr/local/cuda/include
export CPLUS_INCLUDE_PATH=/usr/local/cuda/include
export LIBRARY_PATH=/usr/local/cuda/lib64
%endif

# hipFile: Not tied to a particular ROCm version.
./configure \
 %{?with_hipfile:--enable-libhipfile} \
 %{?with_nbd:--enable-libnbd} \
 %{!?with_xnvme:--disable-xnvme} \
 %{?with_cuda:--enable-cuda --enable-libcufile} \
 --disable-optimizations \
 --dynamic-libengines 

EXTFLAGS="$RPM_OPT_FLAGS" LDFLAGS="$RPM_LD_FLAGS" make V=1 %{?_smp_mflags}

%install
make install prefix=%{_prefix} mandir=%{_mandir} libdir=%{_libdir}/fio DESTDIR=$RPM_BUILD_ROOT INSTALL="install -p"

%files
%doc README.rst REPORTING-BUGS HOWTO.rst examples
%doc MORAL-LICENSE GFIO-TODO SERVER-TODO STEADYSTATE-TODO
%license COPYING
%dir %{_datadir}/%{name}
%dir %{_libdir}/fio/
%{_bindir}/*
%{_mandir}/man1/*
%{_datadir}/%{name}/*

%if %{with pmem}
%files engine-dev-dax
%{_libdir}/fio/fio-dev-dax.so
%endif

%files engine-http
%{_libdir}/fio/fio-http.so

%files engine-libaio
%{_libdir}/fio/fio-libaio.so

%if %{with pmem}
%files engine-libpmem
%{_libdir}/fio/fio-libpmem.so
%endif

%if %{with nbd}
%files engine-nbd
%{_libdir}/fio/fio-nbd.so
%endif

%if %{with rados}
%files engine-rados
%{_libdir}/fio/fio-rados.so
%endif

%if %{with rbd}
%files engine-rbd
%{_libdir}/fio/fio-rbd.so
%endif

%if %{with xnvme}
%files engine-xnvme
%{_libdir}/fio/fio-xnvme.so
%endif

%if %{with hipfile}
%files engine-hipfile
%{_libdir}/fio/fio-hipfile.so
%endif

%ifnarch %{arm}
%files engine-rdma
%{_libdir}/fio/fio-rdma.so
%endif

%changelog
* Fri Feb 6 2026 AMD ROCm hipFIle <> - 3.41-1.hipfile
- Add packaging support for the hipFile IO Engine
- CMake/Configure: Add support to build the hipFile IO Engine
- Update to upstream v3.41

* Fri Jan 16 2026 Fedora Release Engineering <releng@fedoraproject.org> - 3.40-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_44_Mass_Rebuild

* Wed Jul 23 2025 Fedora Release Engineering <releng@fedoraproject.org> - 3.40-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_43_Mass_Rebuild

* Thu May 22 2025 Pavel Reichl <preichl@redhat.com> - 3.40-1
- Update to upstream v3.40
- Related: rhbz#2367663

* Mon Mar 10 2025 Yaakov Selkowitz <yselkowi@redhat.com> - 3.39-3
- Properly enable tcmalloc, only in Fedora
- Related: rhbz#2299495

* Fri Mar 07 2025 Pavel Reichl <preichl@redhat.com> - 3.39-2
- Add dependency on gperftools-libs
- Related: rhbz#2299495

* Mon Feb 24 2025 Pavel Reichl <preichl@redhat.com> - 3.39-1
- Update to upstream version
- Related: rhbz#2316181

* Thu Jan 16 2025 Fedora Release Engineering <releng@fedoraproject.org> - 3.37-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_42_Mass_Rebuild

* Wed Jul 17 2024 Fedora Release Engineering <releng@fedoraproject.org> - 3.37-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_41_Mass_Rebuild

* Tue May 21 2024 Daniel Letai <dani@letai.org.il> - 3.37-2
- Added support for xnvma, cuda (and cufile)

* Wed Mar 27 2024 Pavel Reichl <preichl@redhat.com> - 3.37-1
- Rebase to upstream version 3.37
- Related: rhbz#2271677

* Wed Jan 24 2024 Fedora Release Engineering <releng@fedoraproject.org> - 3.36-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Fri Jan 19 2024 Fedora Release Engineering <releng@fedoraproject.org> - 3.36-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_40_Mass_Rebuild

* Fri Oct 20 2023 Pavel Reichl <preichl@redhat.com> - 3.36.1
- Rebase to upstream version 3.36
- Related: rhbz#2245247

* Tue Oct 03 2023 Pavel Reichl <preichl@redhat.com> - 3.35-5
- Convert License tag to SPDX format

* Wed Jul 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 3.35-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_39_Mass_Rebuild

* Thu Jul 06 2023 Yaakov Selkowitz <yselkowi@redhat.com> - 3.35-3
- Re-enable rados, rbd on ppc64le

* Mon Jun 12 2023 Yaakov Selkowitz <yselkowi@redhat.com> - 3.35-2
- Drop libpmem support from RHEL 10+ builds

* Wed May 24 2023 Pavel Reichl <preichl@redhat.com> - 3.35-1
- New upstream version (RHBZ#2209407)

* Fri Mar 24 2023 Pavel Reichl <preichl@redhat.com> - 3.34-1
- New upstream version (RHBZ#2178183)
- Drop support for pmeblk https://github.com/axboe/fio/commit/04c1cdc

* Thu Jan 19 2023 Fedora Release Engineering <releng@fedoraproject.org> - 3.33-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_38_Mass_Rebuild

* Mon Nov 07 2022 Pavel Reichl <preichl@redhat.com> - 3.33-1
- New upstream version (RHBZ#2140453)

* Thu Sep 08 2022 Davide Cavalca <dcavalca@fedoraproject.org> - 3.32-3
- Make it buildable on RHEL again

* Wed Sep 07 2022 Amit Shah <amitshah@fedoraproject.org> - 3.32-2
- Allow building without nbd, rbd, rados support

* Wed Sep 07 2022 Davide Cavalca <dcavalca@fedoraproject.org> - 3.32-1
- New upstream version (RHBZ#2033897)

* Wed Aug 10 2022 Eric Sandeen <sandeen@redhat.com> - 3.31-1
- New upstream version
- Revert with/without change below, does not pass build

* Wed Jul 27 2022 Amit Shah <amitshah@fedoraproject.og> - 3.30-3
- Allow building without nbd, rbd, rados support

* Thu Jul 21 2022 Fedora Release Engineering <releng@fedoraproject.org> - 3.30-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_37_Mass_Rebuild

* Thu Apr 07 2022 Eric Sandeen <sandeen@redhat.com> - 3.30-1
- New upstream version

* Wed Jan 26 2022 Eric Sandeen <sandeen@redhat.com> - 3.29-1
- New upstream version
- Drop librbd for ppc64le as ceph no longer builds for that arch

* Thu Jan 20 2022 Fedora Release Engineering <releng@fedoraproject.org> - 3.28-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_36_Mass_Rebuild

* Tue Sep 14 2021 Sahana Prasad <sahana@redhat.com> - 3.28-2
- Rebuilt with OpenSSL 3.0.0

* Thu Sep 09 2021 Eric Sandeen <sandeen@redhat.com> - 3.28-1
- New upstream version

* Mon Aug 23 2021 Eric Sandeen <sandeen@redhat.com> - 3.27-3
- Fix FTBFS for new kernel headers (raw device support is gone)
- Fix crash with --enghelp option

* Wed Jul 21 2021 Fedora Release Engineering <releng@fedoraproject.org> - 3.27-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_35_Mass_Rebuild

* Thu Jun 17 2021 Eric Sandeen <sandeen@redhat.com> - 3.27-1
- New upstream version
- Add signature check

* Tue May 18 2021 Eric Sandeen <sandeen@redhat.com> - 3.26-2
- Another fix for dynamic engines (#1956963)

* Fri Mar 12 2021 Eric Sandeen <sandeen@redhat.com> - 3.26-1
- New upstream version

* Mon Feb 08 2021 Eric Sandeen <sandeen@redhat.com> - 3.25-3
- Fix segfault with external IO engines and multiple threads
- Enable dev-dax, pmemblk, libpmem engines for ppc64le

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 3.25-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Fri Dec 04 2020 Eric Sandeen <sandeen@redhat.com> 3.25-1
- New upstream version

* Thu Nov 12 2020 Eric Sandeen <sandeen@redhat.com> 3.24-1
- New upstream version
- Fix dynamic engine loading (#bz1894616)

* Mon Oct 05 2020 Richard W.M. Jones <rjones@redhat.com> 3.23-5
- Disable automatic provides for fio engines (RHBZ#1884954).
- Apply patch to change SONAME of fio engines (see comment 8 of above bug).

* Thu Oct 01 2020 Richard W.M. Jones <rjones@redhat.com> 3.23-3
- Add soft dependencies from main package to all the subpackages.

* Thu Oct 01 2020 Richard W.M. Jones <rjones@redhat.com> 3.23-2
- Enable dynamically loaded engines support.
- Move license to %%license section.

* Tue Sep 08 2020 Eric Sandeen <sandeen@redhat.com> 3.23-1
- New upstream version

* Mon Jul 27 2020 Fedora Release Engineering <releng@fedoraproject.org> - 3.21-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Mon Jul 20 2020 Eric Sandeen <sandeen@redhat.com> 3.21-1
- New upstream version

* Wed Jun 03 2020 Eric Sandeen <sandeen@redhat.com> 3.20-1
- New upstream version

* Fri May 15 2020 Martin Bukatovic <mbukatov@redhat.com> 3.19-3
- Enable http engine. (#1836323)

* Thu Apr 16 2020 Eric Sandeen <sandeen@redhat.com> 3.19-2
- Bugfix update: stat: eliminate extra log samples

* Thu Mar 12 2020 Eric Sandeen <sandeen@redhat.com> 3.19-1
- New upstream version

* Thu Feb 13 2020 Eric Sandeen <sandeen@redhat.com> 3.18-1
- New upstream version
- Fix gcc10 build

* Tue Jan 28 2020 Fedora Release Engineering <releng@fedoraproject.org> - 3.17-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Mon Dec 16 2019 Eric Sandeen <sandeen@redhat.com> 3.17-1
- New upstream version

* Wed Nov 06 2019 Richard W.M. Jones <rjones@redhat.com> 3.16-2
- Enable Network Block Device (libnbd) engine.

* Sat Sep 21 2019 Eric Sandeen <sandeen@redhat.com> 3.16-1
- New upstream version

* Fri Aug 16 2019 Eric Sandeen <sandeen@redhat.com> 3.15-1
- New upstream version

* Thu Aug 08 2019 Eric Sandeen <sandeen@redhat.com> 3.14-3
- Make all scripts explicitly call python3 (#1738819)

* Thu Jul 25 2019 Fedora Release Engineering <releng@fedoraproject.org> - 3.14-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Wed May 22 2019 Eric Sandeen <sandeen@redhat.com> 3.14-1
- New upstream version

* Thu Feb 14 2019 Eric Sandeen <sandeen@redhat.com> 3.13-1
- New upstream version

* Thu Jan 31 2019 Fedora Release Engineering <releng@fedoraproject.org> - 3.12-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Thu Jan 17 2019 Eric Sandeen <sandeen@redhat.com> 3.12-1
- New upstream version

* Wed Aug 22 2018 Eric Sandeen <sandeen@redhat.com> 3.8-1
- New upstream version

* Fri Jul 13 2018 Fedora Release Engineering <releng@fedoraproject.org> - 3.7-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Fri Jun 01 2018 Eric Sandeen <sandeen@redhat.com> 3.7-1
- New upstream version

* Fri Jun 01 2018 Eric Sandeen <sandeen@redhat.com> 3.6-3
- Complete the conversion to python3

* Wed May 16 2018 Eric Sandeen <sandeen@redhat.com> 3.6-2
- Make all python scripts python3 compliant and explicit

* Wed Apr 18 2018 Eric Sandeen <sandeen@redhat.com> 3.6-1
- New upstream version

* Mon Feb 26 2018 Eric Sandeen <sandeen@redhat.com> 3.4-2
- BuildRequires: gcc

* Fri Feb 16 2018 Eric Sandeen <sandeen@redhat.com> 3.4-1
- New upstream version

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 3.3-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Thu Feb  1 2018 Florian Weimer <fweimer@redhat.com> - 3.3-2
- Build with linker flags from redhat-rpm-config

* Wed Dec 27 2017 Eric Sandeen <sandeen@redhat.com> 3.3-1
- New upstream version

* Mon Nov 06 2017 Eric Sandeen <sandeen@redhat.com> 3.2-1
- New upstream version

* Wed Oct 25 2017 Dan Horák <dan[at]danny.cz> 3.1-3
- Add build deps for s390x

* Tue Oct 24 2017 Eric Sandeen <sandeen@redhat.com> 3.1-2
- Add new build deps for more features

* Wed Oct 18 2017 Eric Sandeen <sandeen@redhat.com> 3.1-1
- New upstream version

* Fri Aug 25 2017 Adam Williamson <awilliam@redhat.com> - 3.0-3
- Re-enable ceph deps on ppc64 (it's building again)
- Disable RDMA support on 32-bit ARM (#1484155)

* Thu Aug 17 2017 Eric Sandeen <sandeen@redhat.com> 3.0-2
- Include more files as doc (#1482372)

* Wed Aug 16 2017 Eric Sandeen <sandeen@redhat.com> 3.0-1
- New upstream version

* Mon Jul 31 2017 Eric Sandeen <sandeen@redhat.com> 2.99-3
- Exclude ceph-related deps on ppc64

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 2.99-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Mon Jul 10 2017 Eric Sandeen <sandeen@redhat.com> 2.99-1
- New upstream version

* Fri Jun 16 2017 Eric Sandeen <sandeen@redhat.com> 2.21-1
- New upstream version

* Wed Apr 05 2017 Eric Sandeen <sandeen@redhat.com> 2.19-2
- Enable dev-dax engine on x86_64

* Wed Apr 05 2017 Eric Sandeen <sandeen@redhat.com> 2.19-1
- New upstream version

* Thu Feb 23 2017 Eric Sandeen <sandeen@redhat.com> 2.18-1
- New upstream version

* Thu Feb 23 2017 Eric Sandeen <sandeen@redhat.com> 2.17-1
- New upstream version

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 2.16-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Tue Dec 20 2016 Eric Sandeen <sandeen@redhat.com> 2.16-1
- New upstream version

* Sat Nov 19 2016 Peter Robinson <pbrobinson@fedoraproject.org> 2.15-2
- Rebuild (Power64)

* Thu Oct 27 2016 Eric Sandeen <sandeen@redhat.com> 2.15-1
- New upstream version

* Tue Oct 04 2016 Eric Sandeen <sandeen@redhat.com> 2.14-1
- New upstream version

* Mon Aug 29 2016 Eric Sandeen <sandeen@redhat.com> 2.13-1
- New upstream version

* Wed Jun 15 2016 Eric Sandeen <sandeen@redhat.com> 2.12-1
- New upstream version

* Wed May 25 2016 Eric Sandeen <sandeen@redhat.com> 2.11-1
- New upstream version

* Fri Apr 29 2016 Eric Sandeen <sandeen@redhat.com> 2.9-1
- New upstream version

* Thu Mar 17 2016 Eric Sandeen <sandeen@redhat.com> 2.8-1
- New upstream version

* Fri Mar 11 2016 Eric Sandeen <sandeen@redhat.com> 2.7-1
- New upstream version

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 2.6-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Wed Jan 27 2016 Eric Sandeen <sandeen@redhat.com> 2.6-1
- New upstream version

* Thu Jan 14 2016 Eric Sandeen <sandeen@redhat.com> 2.3-1
- New upstream version

* Mon Dec 21 2015 Eric Sandeen <sandeen@redhat.com> 2.2.13-1
- New upstream version
- Add librdmacm-devel as build dependency (enable RDMA)

* Tue Nov 10 2015 Eric Sandeen <sandeen@redhat.com> 2.2.11-1
- New upstream version
- Add zlib-devel as build dependency

* Tue Sep 22 2015 Eric Sandeen <sandeen@redhat.com> 2.2.10-1
- New upstream version

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.2.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Thu May 07 2015 Eric Sandeen <sandeen@redhat.com> 2.2.8-1
- New upstream version

* Wed Apr 15 2015 Eric Sandeen <sandeen@redhat.com> 2.2.7-1
- New upstream version
- Add librbd ioengine support

* Fri Apr 10 2015 Eric Sandeen <sandeen@redhat.com> 2.2.6-1
- New upstream version

* Tue Feb 17 2015 Eric Sandeen <sandeen@redhat.com> 2.2.5-1
- New upstream version

* Mon Jan 05 2015 Eric Sandeen <sandeen@redhat.com> 2.2.4-1
- New upstream version

* Fri Jan 02 2015 Eric Sandeen <sandeen@redhat.com> 2.2.3-1
- New upstream version

* Wed Nov 12 2014 Eric Sandeen <sandeen@redhat.com> 2.1.14-1
- New upstream version

* Wed Sep 17 2014 Eric Sandeen <sandeen@redhat.com> 2.1.12-1
- New upstream version

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.1.11-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Tue Jul 15 2014 Eric Sandeen <sandeen@redhat.com> 2.1.11-1 
- New upstream version

* Mon Jun 16 2014 Eric Sandeen <sandeen@redhat.com> 2.1.10-1 
- New upstream version

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.1.9-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Tue May 13 2014 Eric Sandeen <sandeen@redhat.com> 2.1.9-1 
- New upstream version

* Mon Apr 14 2014 Eric Sandeen <sandeen@redhat.com> 2.1.8-1 
- New upstream version

* Mon Apr 07 2014 Eric Sandeen <sandeen@redhat.com> 2.1.7-1 
- New upstream version

* Wed Feb 12 2014 Eric Sandeen <sandeen@redhat.com> 2.1.5-1 
- New upstream version

* Wed Sep 25 2013 Eric Sandeen <sandeen@redhat.com> 2.1.3-1 
- New upstream version

* Thu Aug 08 2013 Eric Sandeen <sandeen@redhat.com> 2.1.2-1 
- New upstream version

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Wed May 15 2013 Eric Sandeen <sandeen@redhat.com> 2.1-1 
- New upstream version

* Wed Apr 17 2013 Eric Sandeen <sandeen@redhat.com> 2.0.15-1 
- New upstream version

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.13-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Wed Jan  9 2013 Peter Robinson <pbrobinson@fedoraproject.org> 2.0.13-1
- New upstream 2.0.13 release

* Tue Jan 01 2013 Dan Horák <dan[at]danny.cz> - 2.0.12.2-2
- fix build on arches without ARCH_HAVE_CPU_CLOCK (arm, s390)

* Fri Dec 21 2012 Eric Sandeen <sandeen@redhat.com> 2.0.12.2-1 
- New upstream version

* Sat Nov 24 2012 Eric Sandeen <sandeen@redhat.com> 2.0.11-1 
- New upstream version

* Thu Nov 15 2012 Peter Robinson <pbrobinson@fedoraproject.org> 2.0.10-2
- Merge latest from F16 to master, bump release

* Fri Oct 12 2012 Eric Sandeen <sandeen@redhat.com> 2.0.10-1 
- New upstream version

* Thu Jul 19 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Fri Jul 13 2012 Eric Sandeen <sandeen@redhat.com> 2.0.8-1
- New upstream version

* Fri Mar 23 2012 Eric Sandeen <sandeen@redhat.com> 2.0.6-1
- New upstream version

* Tue Feb 28 2012 Eric Sandeen <sandeen@redhat.com> 2.0.5-1
- New upstream version

* Mon Jan 23 2012 Eric Sandeen <sandeen@redhat.com> 2.0.1-1
- New upstream version

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Dec 08 2011 Eric Sandeen <sandeen@redhat.com> 2.0-1
- New upstream version

* Fri Nov 11 2011 Eric Sandeen <sandeen@redhat.com> 1.99.12-1
- New upstream version

* Tue Sep 27 2011 Eric Sandeen <sandeen@redhat.com> 1.58-1
- New upstream version

* Thu Aug 11 2011 Eric Sandeen <sandeen@redhat.com> 1.57-1
- New upstream version

* Tue May 31 2011 Eric Sandeen <sandeen@redhat.com> 1.55-1
- New upstream version

* Mon May 09 2011 Eric Sandeen <sandeen@redhat.com> 1.53-1
- New upstream version

* Fri Apr 29 2011 Eric Sandeen <sandeen@redhat.com> 1.52-1
- New upstream version

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.50.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Fri Jan 28 2011 Eric Sandeen <sandeen@redhat.com> 1.50.2-1
- New upstream version

* Wed Jan 26 2011 Eric Sandeen <sandeen@redhat.com> 1.50-1
- New upstream version

* Wed Dec 15 2010 Eric Sandeen <sandeen@redhat.com> 1.44.3-1
- New upstream version

* Fri Oct 22 2010 Eric Sandeen <sandeen@redhat.com> 1.44.1-1
- New upstream version

* Fri Oct 22 2010 Eric Sandeen <sandeen@redhat.com> 1.44-1
- New upstream version

* Thu Sep 23 2010 Eric Sandeen <sandeen@redhat.com> 1.43.2-1
- New upstream version

* Tue Jun 29 2010 Eric Sandeen <sandeen@redhat.com> 1.41.5-1
- New upstream version

* Tue Jun 22 2010 Eric Sandeen <sandeen@redhat.com> 1.41.3-1
- New upstream version

* Tue Jun 22 2010 Eric Sandeen <sandeen@redhat.com> 1.41-1
- New upstream version

* Fri Jun 18 2010 Eric Sandeen <sandeen@redhat.com> 1.40-1
- New upstream version

* Thu Jun 03 2010 Eric Sandeen <sandeen@redhat.com> 1.39-1
- New upstream version

* Tue Mar 23 2010 Eric Sandeen <sandeen@redhat.com> 1.38-1
- New upstream version

* Tue Feb 23 2010 Eric Sandeen <sandeen@redhat.com> 1.37-1
- New upstream version

* Tue Dec 15 2009 Eric Sandeen <sandeen@redhat.com> 1.36-1
- New upstream version

* Thu Nov 05 2009 Eric Sandeen <sandeen@redhat.com> 1.35-1
- New upstream version

* Mon Sep 14 2009 Eric Sandeen <sandeen@redhat.com> 1.34-1
- New upstream version

* Thu Sep 10 2009 Eric Sandeen <sandeen@redhat.com> 1.33.1-1
- New upstream version

* Tue Sep 08 2009 Eric Sandeen <sandeen@redhat.com> 1.33-1
- New upstream version

* Fri Jul 31 2009 Eric Sandeen <sandeen@redhat.com> 1.32-1
- New upstream version

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.31-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Sat Jul 11 2009 Eric Sandeen <sandeen@redhat.com> 1.31-1
- Much newer upstream version

* Fri Mar 06 2009 Eric Sandeen <sandeen@redhat.com> 1.24-1
- New upstream version

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.23-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Thu Nov 20 2008 Eric Sandeen <sandeen@redhat.com> 1.23-1
- New upstream version, several bugs fixed.

* Mon Oct 13 2008 Eric Sandeen <sandeen@redhat.com> 1.22-1
- New upstream version, several bugs fixed.

* Thu Jun 19 2008 Eric Sandeen <sandeen@redhat.com> 1.21-1
- New upstream version
- Build verbosely and with RPM cflags

* Fri Apr 25 2008 Eric Sandeen <sandeen@redhat.com> 1.20-1
- New upstream version

* Thu Apr 10 2008 Eric Sandeen <sandeen@redhat.com> 1.19-1
- New upstream version

* Wed Feb 13 2008 Eric Sandeen <sandeen@redhat.com> 1.18-1
- Initial build
