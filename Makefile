
all:
	gcc *.c *.s -o test -lcrypto -lssl -L /usr/local/lib/
clean:
	rm -rf test
