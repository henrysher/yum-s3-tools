Name:		yum-s3-plugin
Version:        0.4.0
Release:	1
Summary:	Amazon S3 Plugin for Yum
License:	Apache License 2.0
URL:		git@github.com:HenryHuang/yum-s3-plugin.git
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
Requires:	yum 

%description
Amazon S3 Plugins for Yum.

%prep
cat $RPM_SOURCE_DIR/yum-s3.tar.gz | tar -zxvf -
find .

%install
rm -rf "${RPM_BUILD_ROOT}"

mkdir -p ${RPM_BUILD_ROOT}/etc/yum.repos.d/
cp -v src/s3iam.repo ${RPM_BUILD_ROOT}/etc/yum.repos.d/

mkdir -p ${RPM_BUILD_ROOT}/etc/yum/pluginconf.d/
cp -v src/s3iam.conf ${RPM_BUILD_ROOT}/etc/yum/pluginconf.d/

mkdir -p ${RPM_BUILD_ROOT}/usr/lib/yum-plugins/
cp -v src/s3iam.py  ${RPM_BUILD_ROOT}/usr/lib/yum-plugins/

%clean
rm -rf "${RPM_BUILD_ROOT}"

%files
%defattr(-,root,root,-)
/etc/yum.repos.d/s3iam.repo
/etc/yum/pluginconf.d/s3iam.conf
/usr/lib/yum-plugins/s3iam.py

%changelog
