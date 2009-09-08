##
## Note that BLOCK_IP_FRAG_OVERLAP will always *block* fragmented IP datagrams of which
## the fragments are overlapping.. 
##

CC=gcc
CFLAGS=	-Wall -lcurses -lpcap -lthr `xml2-config --cflags` -DWITH_SYSLOG -DBLOCK_IP_FRAG_OVERLAP
LIBS= -lpcre
LIBDIRS= -L. -L /usr/local/lib/ `xml2-config --libs`
INCLUDES= -I. -I /usr/local/include/ -I ../includes/
HASHTEST=testhash.c hash.c
HOOKS=detect_hooks/*.c
SRCS= main.c traffic.c timer.c divert.c log.c util.c pcap.c signature.c ip4.c config.c analyze.c stats.c tcp.c hash.c control.c memory.c list.c hooks.c ${HOOKS}
PROGNAME=FreeIPS

all:   
	${CC} -O1 -g ${LIBDIRS} ${LIBS} ${INCLUDES} ${CFLAGS} -o ${PROGNAME} ${SRCS} -lpcap
optimal:
	${CC} -O1 -march=prescott ${LIBDIRS} ${LIBS} ${INCLUDES} ${CFLAGS} -o ${PROGNAME} ${SRCS} -lpcap
	strip ${PROGNAME}
prof:   
	${CC} -g ${LIBDIRS} ${LIBS} ${INCLUDES} ${CFLAGS} -pg -o ${PROGNAME} ${SRCS} -lpcap
pcap:
	${CC} -g ${LIBDIRS} ${LIBS} ${INCLUDES} ${CFLAGS} -o ${PROGNAME} ${SRCS} 
debug:   
	#${CC} -g -ggdb ${LIBS} ${INCLUDES} ${LIBDIRS} ${CFLAGS} -o ${PROGNAME} ${SRCS}
	${CC} -g -ggdb -DWITH_DEBUG -DTCP_SESSION_DEBUG ${LIBS} ${INCLUDES} ${LIBDIRS} ${CFLAGS} -o ${PROGNAME} ${SRCS}
clean:
	rm -f pcap *.o *.a tests/*.o tests/*.core *.core *.o *.so

dist: clean
	cd .. && tar -zcvf IDS.tgz IDS


