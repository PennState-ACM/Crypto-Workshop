CC=gcc
CFLAGS=-std=c99 -ggdb -Wall -Wextra

.PHONY: aes_dec aes_enc

all: aes_enc aes_dec

aes_enc:
	$(CC) $(CFLAGS) -o bin/aes_enc src/aes_enc.c src/aes.c -lcrypto

aes_dec:
	$(CC) $(CFLAGS) -o bin/aes_dec src/aes_dec.c src/aes.c -lcrypto

test:
	bin/aes_enc
	bin/aes_dec

clean:
	rm -f src/*.o bin/aes_enc bin/aes_dec
