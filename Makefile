CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -DVERSION=\"$(VERSION)\"
LDFLAGS = -lncurses -lpthread
VERSION = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

SRC = src/main.c src/packet.c src/buffer.c src/capture.c src/filter.c src/dns.c src/export.c src/ui.c
OBJ = $(SRC:.c=.o)
BIN = wraith

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	chmod 755 $(BIN)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(BIN)

install: $(BIN)
	install -Dm755 $(BIN) /usr/local/bin/$(BIN)

uninstall:
	rm -f /usr/local/bin/$(BIN)

.PHONY: all clean install uninstall