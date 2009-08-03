CC=gcc
CFLAGS=	-Wall -DWITH_DEBUG -llinkedlist -pthread
SRCS=sort_test.c

all:   
	${CC} -g -I. -I ../../ -L ../../ ${CFLAGS} -o sort_test ${SRCS}

clean:
	rm -f sort_test *.o *.a *.core *.o *.so

