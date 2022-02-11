CC=gcc
CFLAGS=-Wall -Wextra -Wpedantic

c2_client: client.o 
	$(CC) $(CFLAGS) -o c2_client client.o 

client.o: client.c
	$(CC) $(CFLAGS) -c client.c

clean:
	rm client.o c2_client