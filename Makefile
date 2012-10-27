
all: clean yum-s3
yum-s3:
	echo "yum-s3..."
	mkdir -p tmp/BUILD tmp/RPMS tmp/SRPMS tmp/SOURCES tmp/SPECS
	tar cvzpf tmp/SOURCES/yum-s3.tar.gz src/*
	rm -rf tmp/BUILDROOT
	rpmbuild --define "_topdir `pwd`/tmp" --buildroot `pwd`/tmp/BUILDROOT -ba pkgs/s3iam.spec -vv
	mkdir -p output/
	cp -rf tmp/SRPMS/* output/
	find tmp/RPMS -name "*.rpm" -exec cp {} output/ \;
clean:
	rm -rf tmp
	rm -rf output


