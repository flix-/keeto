%global beta_tag beta
%global top_level_directory %{name}-%{version}-%{beta_tag}

Name: keeto
Version: 0.4.0
Release: 0.1.%{beta_tag}%{?dist}
Summary: Key and Access Management for OpenSSH
License: GPLv3+
URL: https://keeto.io
Source0: https://keeto.io/static/downloads/%{name}-%{version}-%{beta_tag}/%{name}-%{version}-%{beta_tag}.tar.gz
BuildRequires: gcc
BuildRequires: make
BuildRequires: pkgconfig
BuildRequires: pam-devel
BuildRequires: libconfuse-devel >= 2.7
BuildRequires: check-devel >= 0.9.9
BuildRequires: openssl-devel >= 1.0
BuildRequires: openldap-devel
Requires: openssl-perl
Requires: openssh-server%{?_isa} >= 6.2

%description
Keeto is a module for OpenSSH that enables profile-based administration
of access permissions in a central LDAP aware Directory Service, adds
support for X.509 certificates and handles the distribution of OpenSSH
key material in an automated and secure manner.

%prep
%setup -q -n %{top_level_directory}

%build
%configure --libdir=%{_libdir}/security
%make_build

%install
%make_install
install --directory %{buildroot}/etc/ssh/authorized_keys
install --directory %{buildroot}/etc/ssh/cert_store
install samples/keeto.conf %{buildroot}/etc/ssh/

%check
make check

%files
%{_libdir}/security/pam_keeto.so
%exclude %{_libdir}/security/pam_keeto.la
%{_libdir}/security/pam_keeto_audit.so
%exclude %{_libdir}/security/pam_keeto_audit.la
%dir %attr(0755, root, root) /etc/ssh/authorized_keys
%dir %attr(0755, root, root) /etc/ssh/cert_store
%config(noreplace) %attr(0600, root, root) /etc/ssh/keeto.conf
%doc samples
%doc AUTHORS
%doc ChangeLog
%doc INSTALL
%doc NEWS
%doc README
%license COPYING

%changelog
* Sun Apr 01 2018 Sebastian Roland <seroland86@gmail.com> - 0.4.0-0.1.beta
- Bump version.

* Sat Apr 15 2017 Sebastian Roland <seroland86@gmail.com> - 0.3.0-0.1.beta
- Relaxed directory permissions.
- Removed 'openssh' dependency as it is automatically provided via 'openssh-server'.
- Removed libtool archive files.

* Sun Feb 26 2017 Sebastian Roland <seroland86@gmail.com> - 0.2.0-0.2.beta
- Added 'c_rehash' as dependency which is required to create symlinks in certificate store.

* Sat Feb 04 2017 Sebastian Roland <seroland86@gmail.com> - 0.2.0-0.1.beta
- Initial package.

