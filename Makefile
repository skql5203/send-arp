CC=gcc
CFLAGS=-Wall
LIBS=-lpcap

all: send-arp

send-arp: main.o
	$(CC) $(CFLAGS) -o send-arp main.o $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f send-arp *.o
