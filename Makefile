CC = clang
CFLAGS = -g -Werror -Wall -Wextra -Wpedantic $(shell pkg-config --cflags gmp)
TARGETONE = encrypt 
TARGETTWO = decrypt
TARGETTHREE = keygen
LFLAGS = $(shell pkg-config --libs gmp) -lm

OBJECTSONE = encrypt.o numtheory.o randstate.o rsa.o
OBJECTSTWO = decrypt.o numtheory.o randstate.o rsa.o
OBJECTSTHREE = keygen.o numtheory.o randstate.o rsa.o

all: $(TARGETONE) $(TARGETTWO) $(TARGETTHREE)

$(TARGETONE): $(OBJECTSONE)
	$(CC) $^ -o $@ $(LFLAGS)

$(TARGETTWO): $(OBJECTSTWO)
	$(CC) $^ -o $@ $(LFLAGS)

$(TARGETTHREE): $(OBJECTSTHREE)
	$(CC) $^ -o $@ $(LFLAGS)

%.o: %.c 
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) -f $(TARGETONE) $(TARGETTWO) $(TARGETTHREE) *.o

format:
	clang-format -i -style=file *.[ch]

scan-build: clean
	scan-build --use-cc=$(CC) make
