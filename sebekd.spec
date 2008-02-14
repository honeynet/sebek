Summary: Sebek Server 
Name: sebekd
Version: 3.0.3 
Release: 5
License: BSD The Honeynet Project
Group:  honeywall/data_capture 
URL: http://project.honeynet.org/tools/hflow
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}.%{release}-root
BuildRequires: libtool automake autoconf

###########################################################
# Parameter     %pre    %post    %preun  %postun          #
# 1st install     1       1        N/C     N/C            #
# Upgrade         2       2         1       1             #
# Removal        N/C     N/C        0       0             #
# Note: "-gt 1" instead of 2 covers more than 2 instances #
###########################################################

%description
Sebekd provides a pcap based sniffer for the capture of Sebek packets.
It also provides a set of scipts for processing the Sebek Data.


%define sebekdir        /usr
%define sebekdata       %{sebekdir}/sebek
%define sebeksbin       %{sebekdir}/sbin


%prep
%setup -n %{name}-%{version}

%build
%configure 
make

rm -rf  $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT%{sebeksbin}

install -m 0550 init.d/sebekd      $RPM_BUILD_ROOT/etc/init.d
install -m 0550 sebekd.pl      $RPM_BUILD_ROOT%{sebeksbin}
install -m 0550 sbk_diag.pl        $RPM_BUILD_ROOT%{sebeksbin}
install -m 0550 sbk_ks_log.pl      $RPM_BUILD_ROOT%{sebeksbin}
install -m 0550 sbk_extract        $RPM_BUILD_ROOT%{sebeksbin}

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
/etc/init.d/sebekd
%{sebeksbin}/sbk_ks_log.pl
%{sebeksbin}/sbk_diag.pl
%{sebeksbin}/sebekd.pl
%{sebeksbin}/sbk_extract


%post 
if [ $1 -eq 1 ]; then
	#--- no other instances must be an install not upgrade
	/sbin/chkconfig --add sebekd

fi

if [ $1 -gt 1 ]; then
	#--- this was an upgrade, make sure to restart the deamons
	/sbin/service sebekd restart

fi



%preun
if [ $1 -eq  0 ]; then
	#--- on uninstall if $1 == 0 then we are removing sebekd
	/etc/init.d/sebekd stop
	/sbin/chkconfig --del sebekd

fi
