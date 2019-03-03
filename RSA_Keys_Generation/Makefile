CPPFLAGS=
CFLAGS=-O0 -g -Wall -Wextra -I${HOME}/lib/gnutls/include
LDLIBS=-L${HOME}/lib/gnutls/lib -lgnutls
CC=gcc

TARGET=rsa
SOURCES=rsa.c
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ $(TARGET)

.PHONY: clean

