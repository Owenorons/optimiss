CC=gcc
CFLAGS= -Wall -g -g3  -pthread -L/usr/lib -lssl -lcrypto

EXES = server client
OBJS= server.o 

all: ${EXES}
server: $(OBJS)
				${CC} ${CFLAGS} -o $@ $^
%.o: %.c
			${CC} ${CFLAGS}  -c -o $@ $^

clean:
			rm -f -r *~ *.o *.dSYM ${EXES}