OBJS	= crypto/haval.o crypto/keccak.o crypto/ripemd.o crypto/sha2.o crypto/sha2big.o crypto/whirlpool.o crypto/blake2b.o crypto/poly1305.o utils/xpimath.o test.o
SOURCE	= crypto/haval.cpp crypto/keccak.cpp crypto/ripemd.cpp crypto/sha2.cpp crypto/sha2big.cpp crypto/whirlpool.cpp crypto/blake2b.c crypto/poly1305.c utils/xpimath.cpp test.c
OUT	    = test.out
CC	    = g++
FLAGS	= -g -c -Wall
LFLAGS	= -lgmp

all: $(OBJS)
	$(CC) -g $(OBJS) -o $(OUT) $(LFLAGS)

crypto/haval.o: crypto/haval.cpp
	$(CC) $(FLAGS) crypto/haval.cpp -std=c++11 -o crypto/haval.o

crypto/keccak.o: crypto/keccak.cpp
	$(CC) $(FLAGS) crypto/keccak.cpp -std=c++11 -o crypto/keccak.o

crypto/ripemd.o: crypto/ripemd.cpp
	$(CC) $(FLAGS) crypto/ripemd.cpp -std=c++11 -o crypto/ripemd.o

crypto/sha2.o: crypto/sha2.cpp
	$(CC) $(FLAGS) crypto/sha2.cpp -std=c++11 -o crypto/sha2.o

crypto/poly1305.o: crypto/poly1305.c
	$(CC) $(FLAGS) crypto/poly1305.c -std=c++11 -o crypto/poly1305.o

crypto/sha2big.o: crypto/sha2big.cpp
	$(CC) $(FLAGS) crypto/sha2big.cpp -std=c++11 -o crypto/sha2big.o

crypto/blake2b.o: crypto/blake2b.c
	$(CC) $(FLAGS) crypto/blake2b.c -std=c++11 -o crypto/blake2b.o

crypto/whirlpool.o: crypto/whirlpool.cpp
	$(CC) $(FLAGS) crypto/whirlpool.cpp -std=c++11 -o crypto/whirlpool.o

utils/magimath.o: utils/xpimath.cpp
	$(CC) $(FLAGS) utils/xpimath.cpp -std=c++11 -o utils/xpimath.o

test.o: test.c
	$(CC) $(FLAGS) test.c -std=c++11


clean:
	rm -f $(OBJS) $(OUT)
