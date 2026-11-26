CC := gcc

TARGET := h2guard_daemon
SRC := source/daemon/h2guard_daemon.c

CFLAGS := -Wall -Wextra -O2 -g
LDFLAGS := -lnetfilter_queue -lm

.PHONY: all clean run

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

run: all
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
