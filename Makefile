CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lncurses -lpthread

SRC = src/main.c src/packet.c src/buffer.c src/capture.c src/filter.c src/dns.c src/export.c src/ui.c
OBJ = $(SRC:.c=.o)
BIN = wraith

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
