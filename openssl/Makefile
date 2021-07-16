CFLAGS = -Wall -g -I/usr/local/opt/openssl/include
LDLIBS = -lcrypto
LDFLAGS = -L/usr/local/opt/openssl/lib

.PHONY: all clean

all: create_write check_proof

create_write: x25519.o point.o create_write.o
check_proof: x25519.o point.o check_proof.o

clean:
	-rm -f create_write create_write.o
	-rm -f check_proof check_proof.o
	-rm -f point.o
	-rm -f x25519.o
	-rm -f write.dat
	-rm -f *~
