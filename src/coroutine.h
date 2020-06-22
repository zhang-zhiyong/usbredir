#ifndef _COROUTINE_H_
#define _COROUTINE_H_
#include "config.h"
#include "continuation.h"
struct coroutine
{
	size_t stack_size;
	void *(*entry)(void *);
	int (*release)(struct coroutine *);
	int exited;
	struct coroutine *caller;
	void *data;
	struct continuation cc;
};

void coroutine_init(struct coroutine *co);

int coroutine_release(struct coroutine *co);

void *coroutine_swap(struct coroutine *from, struct coroutine *to, void *arg);

struct coroutine *coroutine_self(void);

void *coroutine_yieldto(struct coroutine *to, void *arg);

void *coroutine_yield(void *arg);

gboolean coroutine_is_main(struct coroutine *co);

static inline gboolean coroutine_self_is_main(void) {
	return coroutine_self() == NULL || coroutine_is_main(coroutine_self());
}
#endif

