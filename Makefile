TARGETS=stunnel

DEBUG?=0
VERBOSE?=0

CROSS=
CC=$(CROSS)gcc
CFLAGS=-Wall -Werror -pthread
LDFLAGS=-lssl -lcrypto -lpthread
RM:=rm -f

SRCS=stunnel.c
SRCS+=
OBJS=${SRCS:.c=.o}

# debug option
ifeq ($(DEBUG), 1)
CFLAGS+=-O0 -g -DDEBUG
else
CFLAGS+=-O3
endif

# verbose option
ifeq ($(VERBOSE), 1)
Q := 
echo-cmd := @echo $(1) > /dev/null
else
Q := @
echo-cmd := @echo $(1)
endif

all: $(TARGETS)

%.o : %.c
	$(echo-cmd) " CC    $@"
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

stunnel: $(OBJS)
	$(echo-cmd) " LD    $@"
	$(Q)$(CC) $< $(LDFLAGS) -o $@

clean:
	$(echo-cmd) " CLEAN"
	$(Q)$(RM) $(OBJS) $(TARGETS)
