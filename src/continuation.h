#ifndef _CONTINUATION_H_
#define _CONTINUATION_H_

#include "spice-common.h"
#include <stddef.h>
#include <ucontext.h>
#include <setjmp.h>

struct continuation
{
	char *stack;
	size_t stack_size;
	void (*entry)(struct continuation *cc);
	int (*release)(struct continuation *cc);
	ucontext_t uc;
	ucontext_t last;
	int exited;
	jmp_buf jmp;
};
void cc_init(struct continuation *cc);
int cc_release(struct continuation *cc);
int cc_swap(struct continuation *from, struct continuation *to);
#define offset_of(type, member) ((unsigned long)(&((type *)0)->member))
#define container_of(obj, type, member)                                 \
        SPICE_ALIGNED_CAST(type *,                                      \
                           (((char *)obj) - offset_of(type, member)))

#endif

