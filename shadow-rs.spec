Name:           shadow-rs
Version:        0.0.1
Release:        1%{?dist}
Summary:        Memory-safe reimplementation of shadow-utils in Rust
License:        MIT
URL:            https://github.com/shadow-utils-rs/shadow-rs
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.94.0
BuildRequires:  cargo
BuildRequires:  pam-devel
BuildRequires:  libselinux-devel
BuildRequires:  audit-libs-devel
BuildRequires:  libcrypt-devel
BuildRequires:  pkgconf-pkg-config

Conflicts:      shadow-utils

%description
shadow-rs is a complete Rust reimplementation of all 14 Linux shadow-utils
tools. Single multicall binary, 4x faster, 20+ security hardening layers.

%prep
%setup -q

%build
cargo build --release

%install
%make_install PREFIX=%{_prefix}

%files
%license LICENSE
%doc README.md CONTRIBUTING.md
%{_sbindir}/shadow-rs
%{_sbindir}/passwd
%{_sbindir}/useradd
%{_sbindir}/userdel
%{_sbindir}/usermod
%{_sbindir}/groupadd
%{_sbindir}/groupdel
%{_sbindir}/groupmod
%{_sbindir}/pwck
%{_sbindir}/grpck
%{_sbindir}/chage
%{_sbindir}/chpasswd
%{_sbindir}/chfn
%{_sbindir}/chsh
%{_sbindir}/newgrp
