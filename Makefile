CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -O2
PROG=apfs-dump

ifeq ("$(origin V)", "command line")
	BUILD_VERBOSE = $(V)
endif
ifndef BUILD_VERBOSE
	BUILD_VERBOSE = 0
endif

ifeq ($(BUILD_VERBOSE), 1)
	Q =
else
	Q = @
endif

all: $(PROG)

OBJS := main.o

$(PROG): $(OBJS)
	@echo "	   [LD]	   $@"
	$(Q)$(CC) -o $@ $(OBJS)

%.o: %.c
	@echo "	   [CC]	   $@"
	$(Q)$(CC) $(CFLAGS) -c $^

.PHONY: clean
clean:
	@echo "	   [CLEAN] $(PROG)"
	$(Q)rm -f *.o $(PROG)
