CFLAGS = -Wall -g
LDLIBS = -lsodium

.PHONY: all clean

all: create_write check_proof

create_write: point.o create_write.o
check_proof: point.o check_proof.o

clean:
	-rm -f create_write create_write.o
	-rm -f check_proof check_proof.o
	-rm -f point.o
	-rm -f write.dat
	-rm -f *~
