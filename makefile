CFLAGS=-Wall -Wextra -Wpedantic

linux: client.c base32.c 
	gcc $(CFLAGS) -o client client.c base32.c 

windows: 
	x86_64-w64-mingw32-gcc-win32 -o client.exe client.c base32.c $(CFLAGS) -lwsock32 -liphlpapi

clean:
	rm client client.exe
