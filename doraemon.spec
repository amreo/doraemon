Summary: Helps client to join domain and maintain itself
Name: doraemon
Version: 2.0.0
Release: 2.ns6
URL: https://github.com/bglug-it/doraemon/
License: GPLv2+
Packager: Paolo Asperti <paolo@asperti.com>
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-root
BuildRequires: nethserver-devtools > 1.0.1
BuildRequires: hunspell-en
Requires: httpd, php, sudo, php-xml, php-mcrypt
Requires: nethserver-base, nethserver-php
Requires: net-tools
Requires: upstart
Source0:  %{name}-%{version}.tar.gz
BuildArch: noarch

%description
Helps client on a domain network to get information for its maintenance.

%prep
%setup

%build
%{makedocs}
perl createlinks.pl

%install
rm -Rf $RPM_BUILD_ROOT
(cd root ; find . -depth -print | cpio -dump %{buildroot})
rm -f %{name}-%{version}-%{release}-filelist
%{genfilelist} %{buildroot} > %{name}-%{version}-%{release}-filelist
mkdir -p %{buildroot}%{_localstatedir}/log/doraemon
mkdir -p %{buildroot}%{_localstatedir}/cache/doraemon


%pre
#if [ "$1" = 1 ]; then
#  #installation
#fi
if [ "$1" = 2 ]; then
  #upgrade
  /sbin/stop %{name} >/dev/null 2>&1 || :
  DATABASE=/var/lib/doraemon/doraemon.db
  INI=/etc/doraemon.ini
  if [ -f $INI ]; then
    DATABASE=$(awk -F "=" '/Database/ {print $2}' $INI)
    PORT=$(awk -F "=" '/Port/ {print $2}' $INI)
    BASE=$(awk -F "=" '/Base/ {print $2}' $INI)
    ROLE=$(awk -F "=" '/Role/ {print $2}' $INI)
    DIGITS=$(awk -F "=" '/Digits/ {print $2}' $INI)
    DOMAIN=$(awk -F "=" '/Domain/ {print $2}' $INI)
    MGMTKEY=$(awk -F "=" '/MgmtKey/ {print $2}' $INI)
    VAULTPASSFILE=$(awk -F "=" '/VaultPassFile/ {print $2}' $INI)
    rm $INI
    /sbin/e-smith/db configuration set %{name} service \
      status enabled \
      TCPPort $PORT \
      access private \
      DefaultRole $ROLE \
      DomainFile $DOMAIN \
      ManagementKeyFile $MGMTKEY \
      NamingBase $BASE \
      NamingDigits $DIGITS \
      VaultPassFile $VAULTPASSFILE
  else
    /sbin/e-smith/db configuration set %{name} service \
      status enabled \
      TCPPort 3000 \
      access private \
      DefaultRole client \
      DomainFile /etc/domain.yml \
      ManagementKeyFile /home/amgmt/.ssh/id_rsa.pub \
      NamingBase lab \
      NamingDigits 2 \
      VaultPassFile /home/amgmt/.ansible/vault.txt
  fi
  if [ -f $DATABASE ]; then
    sqlite3 -separator " " $DATABASE \
      "select * from client" | while read id hostname mac role; do
      /sbin/e-smith/db hosts set $hostname local \
        MacAddress $mac Role $role
    done
    rm $DATABASE
  fi
fi

%post
/etc/e-smith/events/actions/initialize-default-databases
[ -e /usr/sbin/doraemon ] && [ ! -L /usr/sbin/doraemon ] && rm /usr/sbin/doraemon
[ ! -L /usr/sbin/doraemon ] && ln -s httpd /usr/sbin/doraemon
if [ "$1" = 1 ]; then
  #installation
  /sbin/e-smith/db configuration set %{name} service status enabled TCPPort 3000 access private DefaultRole client DomainFile /etc/domain.yml ManagementKeyFile /home/amgmt/.ssh/id_rsa.pub NamingBase lab NamingDigits 2 VaultPassFile /home/amgmt/.ansible/vault.txt
  /sbin/e-smith/expand-template /etc/sudoers
  /sbin/e-smith/expand-template /etc/httpd/doraemon/httpd.conf
  /sbin/start %{name} >/dev/null 2>&1 || :
  /sbin/e-smith/signal-event runlevel-adjust
  /sbin/e-smith/signal-event firewall-adjust
fi
if [ "$1" = 2 ]; then
  #upgrade
  # TODO: this won't be needed in the next version
  /sbin/e-smith/expand-template /etc/sudoers
  /sbin/e-smith/expand-template /etc/httpd/doraemon/httpd.conf
  /sbin/start %{name} >/dev/null 2>&1 || :
  /sbin/e-smith/signal-event runlevel-adjust
  /sbin/e-smith/signal-event firewall-adjust
fi


%preun
#if [ "$1" = 1 ]; then
#  #upgrade
#fi
if [ "$1" = 0 ]; then
  #uninstallation
  /sbin/stop %{name} >/dev/null 2>&1 || :
fi


%postun
#if [ "$1" = 1 ]; then
#  #upgrade
#fi
if [ "$1" = 0 ]; then
  #uninstallation
  /sbin/e-smith/db configuration delete %{name}
  /sbin/e-smith/expand-template /etc/sudoers
  /sbin/e-smith/signal-event runlevel-adjust
  /sbin/e-smith/signal-event firewall-adjust
fi


%clean
rm -rf %{buildroot}

%files -f %{name}-%{version}-%{release}-filelist
%defattr(0644,root,root,755)
%doc README.md LICENSE.txt
%attr(0644,srvmgr,srvmgr) %ghost %{_localstatedir}/log/doraemon/access_log
%attr(0644,srvmgr,srvmgr) %ghost %{_localstatedir}/log/doraemon/error_log


%changelog
* Mon Jul 18 2016 Paolo Asperti <paolo@asperti.com> - 2.0.0-1
- PHP porting
- Added a basic UI
- Added room support

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
