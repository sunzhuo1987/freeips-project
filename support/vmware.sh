#!/usr/local/bin/bash 

BSDDIR=/usr/src/tools/tools/tinybsd/
BINDISK=tinybsd.bin
RCFILE=rc.local
VMDISK=FreeIPS.vmdk
SVNSERVER=svn.heinen.ws
SVNSUBDIR=anti
SVNCODIR=anti
HERE=`pwd`
BUILDDIR=`pwd`/../
EXCLUDEFILES=delete.files
RELEASEDIR=${HERE}
VMXFILE=freeips.vmx
TMPMNT=/mnt

set -x

##
##
##

TIMESTAMP=`date "+%d-%m-%Y"`

function build_freeips() {
	cd ${BUILDDIR}
	
	make clean
	make 
	export PREFIX=${TMPMNT}/usr/local/
	make install
	make clean

}

function build_tinybsd() {

	if [ -f "${BSDDIR}/${BINDISK}" ]
	then
		/bin/rm -f "${BSDDIR}/${BINDISK}" 
	fi

	cp -R freeips/ /usr/src/tools/tools/tinybsd/conf/freeips/

	echo "Starting to build image";
	/usr/src/tools/tools/tinybsd/tinybsd sectors=128000 heads=8 spt=64 conf=freeips batch new

	if [ ! -f "${BSDDIR}/${BINDISK}" ]
	then
		echo "Build failed !"
		exit 1;
	fi
}

function clean_image() {

	if [ ! -f "${EXCLUDEFILES}" ];
	then
		echo "Exclude files not found"
	fi

	for file in `cat ${EXCLUDEFILES}`;
	do
		rm -f ${TMPMNT}/${EXCLUDEFILES}
	done

	cp /lib/libthr.so.3 ${TMPMNT}/lib/
	cp /lib/libpcap.so.5 ${TMPMNT}/lib/
	cp /lib/libncurses.so.7 ${TMPMNT}/lib/
	cp /usr/local/lib/libpcre.so.0 ${TMPMNT}/usr/lib/
	cp /usr/local/lib/libxml2.so.5 ${TMPMNT}/usr/lib/
	cp /usr/local/lib/libiconv.so.3 ${TMPMNT}/usr/lib/
	cp /boot/*.4th ${TMPMNT}/boot/
	cp motd ${TMPMNT}/etc/
	mkdir -p ${TMPMNT}/usr/chroot/logdir
	mkdir -p ${TMPMNT}/usr/chroot/etc/
	cp chroot/etc/* ${TMPMNT}/usr/chroot/etc/
	mkdir -p ${TMPMNT}/usr/chroot/snort/rules/
	mkdir -p ${TMPMNT}/usr/chroot/support/html/
	cp support/html/* ${TMPMNT}/usr/chroot/support/html/
	chown nobody ${TMPMNT}/usr/chroot/logdir/

	cp ./config.xml ${TMPMNT}/root/

	cp /usr/code/sigs/rules/*  ${TMPMNT}/usr/chroot/snort/rules/

	# Copy startup file
	cp ${HERE}/${RCFILE} ${TMPMNT}/etc
	cp ${HERE}/loader.conf ${TMPMNT}/boot/
}

function mount_image() {
	mdconfig -a -t vnode -f ${BSDDIR}/${BINDISK} -u 0
	mount /dev/md0a ${TMPMNT}
}

function umount_image() {
	umount ${TMPMNT}
	mdconfig -d -u 0
}

function create_vmware_image() {
	echo "Creating VMWare image"
	rm -f ${BSDDIR}/${VMDISK}
	qemu-img convert -O vmdk ${BSDDIR}/${BINDISK} ${BSDDIR}/${VMDISK}
}

function cleanup() {
	#rm -rf ${BUILDDIR}
	echo "Cleanup.."
}

function package() {

	echo "Packaging the VMWare disk"

	cd ${HERE}

	mkdir /var/tmp/FreeIPS-${TIMESTAMP}/
	cp ${BSDDIR}/${VMDISK} /var/tmp/FreeIPS-${TIMESTAMP}/
	cp ${VMXFILE} /var/tmp/FreeIPS-${TIMESTAMP}/
	cd  /var/tmp/
	tar -zcvf FreeIPS-${TIMESTAMP}.tgz FreeIPS-${TIMESTAMP}/
	cp FreeIPS-${TIMESTAMP}.tgz  ${RELEASEDIR}
	cd ${RELEASEDIR}
}

build_tinybsd;
mount_image;
clean_image;
build_freeips;
umount_image;
create_vmware_image;
cleanup;
package;


