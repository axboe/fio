#ifndef SYS_WAIT_H
#define SYS_WAIT_H

#define WIFSIGNALED(a)	0
#define WIFEXITED(a)	0
#define WTERMSIG(a)		0
#define WEXITSTATUS(a)	0
#define WNOHANG			1

pid_t waitpid(pid_t, int *stat_loc, int options);

#endif /* SYS_WAIT_H */
