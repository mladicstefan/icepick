CC=gcc
CFLAGS=-g -Wall -Wextra
LIBS=-lpcap
OBJS=main.o

icepick: $(OBJS)
	$(CC) -o icepick $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) icepick

.PHONY: clean
