CC=gcc
CFLAGS=-O3 -pthread -lsodium
LIBS=-lsodium

all: mini-sidecar mini-ctl

mini-sidecar: mini_sidecar.c mini_crypto.c
	$(CC) $(CFLAGS) mini_sidecar.c mini_crypto.c -o mini-sidecar $(LIBS)

mini-ctl: mini-ctl.c
	$(CC) $(CFLAGS) mini-ctl.c -o mini-ctl

clean:
	rm -f mini-sidecar mini-ctl
