# WineShield Core Makefile
# Compiles C extensions and binaries

CC = gcc
CFLAGS = -Wall -O2 -fPIC
LDFLAGS = -lseccomp

SOURCES = wineshield_seccomp.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = wineshield_seccomp

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
