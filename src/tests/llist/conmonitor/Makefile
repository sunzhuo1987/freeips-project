CC=gcc
CFLAGS=	-Wall -DWITH_DEBUG -llinkedlist -lpcap -pthread
SRCS=connections.c

all:   
	${CC} -g -I. -L. -I ../../ -L ../../ ${CFLAGS} -o connections ${SRCS}

clean:
	rm -f connections *.o *.a tests/*.o tests/*.core *.core *.o *.so


