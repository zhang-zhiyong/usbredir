#include "config.h"
#include <glib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "coroutine.h"

#ifndef MAP_ANONYMOUS
# define MAP_ANONYMOUS MAP_ANON
#endif

int coroutine_release(struct coroutine *co)
{

	return cc_release(&co->cc);
}

static int _coroutine_release(struct continuation *cc)
{
    
	struct coroutine *co = container_of(cc, struct coroutine, cc);

	if (co->release) {
		int ret = co->release(co);
		if (ret < 0)
			return ret;
	}
	munmap(co->cc.stack, co->cc.stack_size);
	co->caller = NULL;
	return 0;
}

static void coroutine_trampoline(struct continuation *cc)
{
	
	struct coroutine *co = container_of(cc, struct coroutine, cc);
	co->data = co->entry(co->data);
}

void coroutine_init(struct coroutine *co)
{
    
	if (co->stack_size == 0)
		co->stack_size = 16 << 20;
	co->cc.stack_size = co->stack_size;
	co->cc.stack = mmap(0, co->stack_size,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS,-1, 0);
	if (co->cc.stack == MAP_FAILED)
		g_error("mmap(%" G_GSIZE_FORMAT ") failed: %s",co->stack_size, g_strerror(errno));
	co->cc.entry = coroutine_trampoline;
	co->cc.release = _coroutine_release;
	co->exited = 0;
	cc_init(&co->cc);
}


static struct coroutine leader;
static struct coroutine *current;

struct coroutine *coroutine_self(void)
{
     
	if (current == NULL)
		current = &leader;
	return current;
}

void *coroutine_swap(struct coroutine *from, struct coroutine *to, void *arg)
{
	
	int ret;
	to->data = arg;
	current = to;
	ret = cc_swap(&from->cc, &to->cc);
	if (ret == 0)
		return from->data;
	else if (ret == 1) {
		coroutine_release(to);
		current = from;
		to->exited = 1;
		return to->data;
	}

	return NULL;
}

void *coroutine_yieldto(struct coroutine *to, void *arg)
{

	g_return_val_if_fail(!to->caller, NULL);
	g_return_val_if_fail(!to->exited, NULL);

	to->caller = coroutine_self();
	return coroutine_swap(coroutine_self(), to, arg);
}

void *coroutine_yield(void *arg)
{

	struct coroutine *to = coroutine_self()->caller;
	if (!to) {
		fprintf(stderr, "Co-routine is yielding to no one\n");
		abort();
	}
	coroutine_self()->caller = NULL;
	return coroutine_swap(coroutine_self(), to, arg);
}

gboolean coroutine_is_main(struct coroutine *co)
{
   
    return (co == &leader);
}

