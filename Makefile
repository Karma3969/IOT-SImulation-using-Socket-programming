CC=gcc
CFLAGS=-Wall -O2

all: server client

server: websocket_server.c utils.c db.c
	$(CC) $(CFLAGS) -o websocket_server websocket_server.c utils.c db.c -lsqlite3 -lssl -lcrypto

client: device_client.c utils.c
	$(CC) $(CFLAGS) -o device_client device_client.c utils.c -lssl -lcrypto

clean:
	rm -f websocket_server device_client smarthome.db
