#ifndef _LINUX_SYSLET_H
#define _LINUX_SYSLET_H
/*
 * The syslet subsystem - asynchronous syscall execution support.
 *
 * Started by Ingo Molnar:
 *
 *  Copyright (C) 2007 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * User-space API/ABI definitions:
 */

#ifndef __user
# define __user
#endif

/*
 * This is the 'Syslet Atom' - the basic unit of execution
 * within the syslet framework. A syslet always represents
 * a single system-call plus its arguments, plus has conditions
 * attached to it that allows the construction of larger
 * programs from these atoms. User-space variables can be used
 * (for example a loop index) via the special sys_umem*() syscalls.
 *
 * Arguments are implemented via pointers to arguments. This not
 * only increases the flexibility of syslet atoms (multiple syslets
 * can share the same variable for example), but is also an
 * optimization: copy_uatom() will only fetch syscall parameters
 * up until the point it meets the first NULL pointer. 50% of all
 * syscalls have 2 or less parameters (and 90% of all syscalls have
 * 4 or less parameters).
 *
 * [ Note: since the argument array is at the end of the atom, and the
 *   kernel will not touch any argument beyond the final NULL one, atoms
 *   might be packed more tightly. (the only special case exception to
 *   this rule would be SKIP_TO_NEXT_ON_STOP atoms, where the kernel will
 *   jump a full syslet_uatom number of bytes.) ]
 */
struct syslet_uatom {
	unsigned long				flags;
	unsigned long				nr;
	long __user				*ret_ptr;
	struct syslet_uatom	__user		*next;
	unsigned long		__user		*arg_ptr[6];
	/*
	 * User-space can put anything in here, kernel will not
	 * touch it:
	 */
	void __user				*private;
};

/*
 * Flags to modify/control syslet atom behavior:
 */

/*
 * Immediately queue this syslet asynchronously - do not even
 * attempt to execute it synchronously in the user context:
 */
#define SYSLET_ASYNC				0x00000001

/*
 * Never queue this syslet asynchronously - even if synchronous
 * execution causes a context-switching:
 */
#define SYSLET_SYNC				0x00000002

/*
 * Do not queue the syslet in the completion ring when done.
 *
 * ( the default is that the final atom of a syslet is queued
 *   in the completion ring. )
 *
 * Some syscalls generate implicit completion events of their
 * own.
 */
#define SYSLET_NO_COMPLETE			0x00000004

/*
 * Execution control: conditions upon the return code
 * of the just executed syslet atom. 'Stop' means syslet
 * execution is stopped and the atom is put into the
 * completion ring:
 */
#define SYSLET_STOP_ON_NONZERO			0x00000008
#define SYSLET_STOP_ON_ZERO			0x00000010
#define SYSLET_STOP_ON_NEGATIVE			0x00000020
#define SYSLET_STOP_ON_NON_POSITIVE		0x00000040

#define SYSLET_STOP_MASK				\
	(	SYSLET_STOP_ON_NONZERO		|	\
		SYSLET_STOP_ON_ZERO		|	\
		SYSLET_STOP_ON_NEGATIVE		|	\
		SYSLET_STOP_ON_NON_POSITIVE		)

/*
 * Special modifier to 'stop' handling: instead of stopping the
 * execution of the syslet, the linearly next syslet is executed.
 * (Normal execution flows along atom->next, and execution stops
 *  if atom->next is NULL or a stop condition becomes true.)
 *
 * This is what allows true branches of execution within syslets.
 */
#define SYSLET_SKIP_TO_NEXT_ON_STOP		0x00000080

/*
 * This is the (per-user-context) descriptor of the async completion
 * ring. This gets passed in to sys_async_exec():
 */
struct async_head_user {
	/*
	 * Current completion ring index - managed by the kernel:
	 */
	unsigned long				kernel_ring_idx;
	/*
	 * User-side ring index:
	 */
	unsigned long				user_ring_idx;

	/*
	 * Ring of pointers to completed async syslets (i.e. syslets that
	 * generated a cachemiss and went async, returning -EASYNCSYSLET
	 * to the user context by sys_async_exec()) are queued here.
	 * Syslets that were executed synchronously (cached) are not
	 * queued here.
	 *
	 * Note: the final atom that generated the exit condition is
	 * queued here. Normally this would be the last atom of a syslet.
	 */
	struct syslet_uatom __user		**completion_ring;

	/*
	 * Ring size in bytes:
	 */
	unsigned long				ring_size_bytes;

	/*
	 * The head task can become a cachemiss thread later on
	 * too, if it blocks - so it needs its separate thread
	 * stack and start address too:
	 */
	unsigned long				head_stack;
	unsigned long				head_eip;

	/*
	 * Newly started async kernel threads will take their
	 * user stack and user start address from here. User-space
	 * code has to check for new_thread_stack going to NULL
	 * and has to refill it with a new stack if that happens.
	 */
	unsigned long				new_thread_stack;
	unsigned long				new_thread_eip;
};

#endif
