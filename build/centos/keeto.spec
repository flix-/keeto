%global beta beta
%global top_level_directory keeto-0.2.0-beta

Name: keeto
Version: 0.2.0
Release: 0.1.%{beta}%{?dist}
Summary: Key and Access Management for OpenSSH
License: GPLv3+
URL: https://keeto.io
Source0: https://keeto.io/static/downloads/keeto-0.2.0-beta/keeto-0.2.0-beta.tar.gz
BuildRequires: gcc
BuildRequires: make
BuildRequires: pkgconfig
BuildRequires: pam-devel
BuildRequires: libconfuse-devel >= 2.7
BuildRequires: check-devel >= 0.9.9
BuildRequires: openssl-devel >= 1.0
BuildRequires: openldap-devel
Requires: openssh >= 6.2
Requires: openssh-server >= 6.2

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
%{_libdir}/security/pam_keeto.la
%{_libdir}/security/pam_keeto.so
%{_libdir}/security/pam_keeto_audit.la
%{_libdir}/security/pam_keeto_audit.so
%dir %attr(0711, root, root) /etc/ssh/authorized_keys
%dir %attr(0700, root, root) /etc/ssh/cert_store
%config(noreplace) %attr(0600, root, root) /etc/ssh/keeto.conf
%doc samples
%doc AUTHORS
%doc ChangeLog
%doc INSTALL
%doc NEWS
%doc README
%license COPYING

%changelog
* Sat Feb 04 2017 Sebastian Roland <seroland86@gmail.com> - 0.2.0-0.1.beta
- Initial package

