CC=gcc
CFLAGS=	-Wall -DWITH_DEBUG -llinkedlist -pthread
SRCS=list_test.c

all:   
	${CC} -g -I. -I ../../ -L ../../ ${CFLAGS} -o list_test ${SRCS}

clean:
	rm -f list_test *.o *.a *.core *.o *.so

