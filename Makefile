PREFIX?=/usr/local

all:   
	cd src && make all
	mv -f src/ANTI .
anti:
	make pcap
debug:   
	cd src && make debug
	mv -f src/ANTI .
list:
	cd src && make -f Makefile.llist thread
clean:
	cd src && rm -f ANTI *.o *.a tests/*.o tests/*.core *.core *.o *.so *.core
	rm -f ANTI ANTI.core
install:
	cp ANTI ${PREFIX}/bin/
	mkdir -p ${PREFIX}/share/ANTI
	cp -r config ${PREFIX}/share/ANTI/

deinstall:
	rm ${PREFIX}/bin/ANTI
	rm -rf ${PREFIX}/share/ANTI

dist: clean
	cd .. && tar -zcvf IDS.tgz IDS


