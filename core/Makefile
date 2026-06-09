# WineShield Core Makefile
# Compiles C extensions and binaries

CC = gcc
CFLAGS = -Wall -O2 -fPIC -D_GNU_SOURCE -DTEST_STANDALONE
LDFLAGS =

SOURCES = syscall_monitor.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = syscall_monitor

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
