CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -O2
PROG=apfs-dump

SRCS=$(wildcard *.c)
HDRS=$(wildcard *.h)
OBJS=$(SRCS:.c=.o)
DEPS=$(SRCS:.c=.d)

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

$(PROG): $(OBJS)
	@echo "	   [LD]	   $@"
	$(Q)$(CC) -o $@ $(OBJS)

$(OBJS): $(SRCS)  $(HDRS)
	@echo "	   [CC]	   $@"
	$(Q)$(CC) $(CFLAGS) -c $^

.PHONY: clean
clean:
	@echo "	   [CLEAN] $(PROG)"
	$(Q)rm -f *.gch *.o *.d $(PROG)
