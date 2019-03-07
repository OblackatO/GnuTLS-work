CPPFLAGS=
CFLAGS=-O0 -g -Wall -Wextra
LDLIBS= -L/usr/lib -lgnutls
CC=gcc

TARGET=ecdsa
SOURCES=ecdsa.c
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ $(TARGET)

.PHONY: clean

