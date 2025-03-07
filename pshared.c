#include <string.h>

#include "log.h"
#include "pshared.h"

int cond_init_pshared(pthread_cond_t *cond)
{
	pthread_condattr_t cattr;
	int ret;

	ret = pthread_condattr_init(&cattr);
	if (ret) {
		log_err("pthread_condattr_init: %s\n", strerror(ret));
		return ret;
	}

#ifdef CONFIG_PSHARED
	ret = pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		log_err("pthread_condattr_setpshared: %s\n", strerror(ret));
		return ret;
	}
#endif

#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
	ret = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	if (ret) {
		log_err("pthread_condattr_setclock: %s\n", strerror(ret));
		return ret;
	}
#endif

	ret = pthread_cond_init(cond, &cattr);
	if (ret) {
		log_err("pthread_cond_init: %s\n", strerror(ret));
		return ret;
	}

	return 0;
}

/*
 * 'type' must be a mutex type, e.g. PTHREAD_MUTEX_NORMAL,
 * PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_RECURSIVE or PTHREAD_MUTEX_DEFAULT.
 */
int mutex_init_pshared_with_type(pthread_mutex_t *mutex, int type)
{
	pthread_mutexattr_t mattr;
	int ret;

	ret = pthread_mutexattr_init(&mattr);
	if (ret) {
		log_err("pthread_mutexattr_init: %s\n", strerror(ret));
		return ret;
	}

	/*
	 * Not all platforms support process shared mutexes (NetBSD/OpenBSD)
	 */
#ifdef CONFIG_PSHARED
	ret = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		log_err("pthread_mutexattr_setpshared: %s\n", strerror(ret));
		return ret;
	}
#endif
	ret = pthread_mutexattr_settype(&mattr, type);
	if (ret) {
		log_err("pthread_mutexattr_settype: %s\n", strerror(ret));
		return ret;
	}
	ret = pthread_mutex_init(mutex, &mattr);
	if (ret) {
		log_err("pthread_mutex_init: %s\n", strerror(ret));
		return ret;
	}
	pthread_mutexattr_destroy(&mattr);

	return 0;
}

int mutex_init_pshared(pthread_mutex_t *mutex)
{
	return mutex_init_pshared_with_type(mutex, PTHREAD_MUTEX_DEFAULT);
}

int mutex_cond_init_pshared(pthread_mutex_t *mutex, pthread_cond_t *cond)
{
	int ret;

	ret = mutex_init_pshared(mutex);
	if (ret)
		return ret;

	ret = cond_init_pshared(cond);
	if (ret)
		return ret;

	return 0;
}
