Summary: Helps client to join domain and maintain itself
Name: doraemon
Version: 1.2.1
Release: 2.ns6
URL: https://github.com/bglug-it/doraemon/
License: GPLv2+
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-root
Requires: python python-bottle python-crypto2.6 perl-config-IniFiles perl-Net-ARP perl-Crypt-ECB perl-Crypt-OpenSSL-AES nethserver-base
Requires(post): chkconfig nethserver-base
Requires(preun): chkconfig initscripts nethserver-base
Source0: doraemon-1.2.1.tar.gz
BuildArch: noarch

%description
Helps client on a domain network to get information for its maintenance.

%prep
%setup -q

%build

%install
rm -rf %{buildroot}
install -d %{buildroot}
install -d -m 755 %{buildroot}%{_sysconfdir}
install -m 644 doraemon.ini %{buildroot}%{_sysconfdir}/%{name}.ini
# Installo il servizio
install -d -m 755 %{buildroot}%{_initrddir}
install -m 755 initrd %{buildroot}%{_initrddir}/%{name}
# Installo lo script vero e proprio
install -d -m 755 %{buildroot}%{_bindir}
install -m 755 doraemon.py %{buildroot}%{_bindir}/%{name}.py
# Cartella del database
install -d %{buildroot}%{_sharedstatedir}/%{name}
# File per il rotate
install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -m 644 doraemon.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
# File di Nethserver
install -d %{buildroot}%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}
install -m 644 type %{buildroot}%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/type
install -m 644 status %{buildroot}%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/status
install -m 644 access %{buildroot}%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/access
install -m 644 TCPPort %{buildroot}%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/TCPPort

%post
if [ "$1" = 1 ]; then
  /sbin/chkconfig --add %{name}
  /sbin/service %{name} start >/dev/null 2>&1
  /sbin/e-smith/db configuration set %{name} service status enabled TCPPort 3000 access private
  /sbin/e-smith/signal-event runlevel-adjust
  /sbin/e-smith/signal-event firewall-adjust
fi

%preun
if [ "$1" = 0 ]; then
  /sbin/e-smith/db configuration delete %{name}
  /sbin/service %{name} stop >/dev/null 2>&1
  chkconfig --del %{name}
  /sbin/e-smith/signal-event runlevel-adjust
  /sbin/e-smith/signal-event firewall-adjust
fi

%clean
rm -rf %{buildroot}

%files
%defattr(644,root,root,755)
%doc README.md LICENSE
%config(noreplace) %{_sysconfdir}/%{name}.ini
%attr(755,-,-) %{_initrddir}/%{name}
%attr(755,-,-) %{_bindir}/%{name}.py

%dir %attr(755,-,-) %{_sharedstatedir}/%{name}
%{_sysconfdir}/logrotate.d/%{name}
%dir %attr(755,-,-) %{_sysconfdir}/e-smith/db/configuration/defaults/%{name}
%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/status
%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/type
%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/access
%{_sysconfdir}/e-smith/db/configuration/defaults/%{name}/TCPPort

%changelog
* Tue Oct 27 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.2.1-2.ns6
- Packing corrections to rpm to fix upgrading issue

* Tue Oct 27 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.2.1-1.ns6
- Packing new minor correction on how packages are extracted from db

* Mon Sep 11 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.2.0-1.ns6
- Packing new version with ansible dynamic inventory support, epoptes server role support.

* Mon Sep 07 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.1.1-1.ns6
- Packing new version with correct roles.

* Sun Sep 06 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.1.0-1.ns6
- Packing new version with new functionalities.

* Wed Jul 15 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.0.0-2.ns6
- Added logrotate file.

* Mon Jul 13 2015 Emiliano Vavassori <syntaxerrormmm-AT-gmail.com> - 1.0.0-1.ns6
- Unique binary for both ansiblehelper and mac2hostname.
