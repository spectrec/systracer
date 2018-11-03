CFLAGS = -ggdb3 \
	 -Wall -Wextra -Werror \
	 -MMD -MP

LDFLAGS = -ggdb3

all: tracer

TRACER_SRCS = src/main.c
TRACER_DEPS = $(patsubst %.c,%.d,${TRACER_SRCS})
TRACER_OBJS = $(patsubst %.c,%.o,${TRACER_SRCS})

tracer: ${TRACER_OBJS}
	$(CC) -o $@ $^ ${CFLAGS} ${LDFLAGS}

-include ${deps}

clean:
	@rm -f ${TRACER_OBJS} ${TRACER_DEPS} tracer

.PHONY: all clean
