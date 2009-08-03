PREFIX?=/usr/local

all:   
	cd src && make all
	mv -f src/FreeIPS .
anti:
	make pcap
debug:   
	cd src && make debug
	mv -f src/FreeIPS .
list:
	cd src && make -f Makefile.llist thread
clean:
	cd src && rm -f FreeIPS *.o *.a tests/*.o tests/*.core *.core *.o *.so *.core
	rm -f FreeIPS ANTI.core
install:
	cp FreeIPS ${PREFIX}/bin/
	mkdir -p ${PREFIX}/share/FreeIPS
	cp -r config ${PREFIX}/share/FreeIPS/

deinstall:
	rm ${PREFIX}/bin/FreeIPS
	rm -rf ${PREFIX}/share/FreeIPS

dist: clean
	cd .. && tar -zcvf IDS.tgz IDS


