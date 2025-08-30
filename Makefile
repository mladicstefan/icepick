CC=gcc
LIBS=-lpcap
DEBUG_OBJS=main_debug.o
RELEASE_OBJS=main_release.o
DEBUG_CFLAGS=-g -Wall -Wextra -DDEBUG -fsanitize=address -fsanitize=undefined
DEBUG_LDFLAGS=-fsanitize=address -fsanitize=undefined
RELEASE_CFLAGS=-O3 -Wall -Werror -DNDEBUG -march=native -flto -ffast-math
RELEASE_LDFLAGS=-flto

all: debug

debug: debug

debug: $(DEBUG_OBJS)
	$(CC) $(DEBUG_CFLAGS) -o icepick_debug $(DEBUG_OBJS) $(LIBS) $(DEBUG_LDFLAGS)

release: release

release: $(RELEASE_OBJS)
	$(CC) $(RELEASE_CFLAGS) -o icepick $(RELEASE_OBJS) $(LIBS) $(RELEASE_LDFLAGS)

%_debug.o: %.c
	$(CC) $(DEBUG_CFLAGS) -c $< -o $@

%_release.o: %.c
	$(CC) $(RELEASE_CFLAGS) -c $< -o $@

clean:
	rm -f $(DEBUG_OBJS) $(RELEASE_OBJS) icepick_debug icepick

.PHONY: all debug release clean
