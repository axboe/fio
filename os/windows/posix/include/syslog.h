#ifndef SYSLOG_H
#define SYSLOG_H

int syslog();

#define LOG_INFO	0x1
#define LOG_ERROR	0x2
#define LOG_WARN	0x4

#define LOG_NDELAY	0x1
#define LOG_NOWAIT	0x2
#define LOG_PID		0x4
#define LOG_USER	0x8

void closelog(void);
void openlog(const char *ident, int logopt, int facility);

#endif /* SYSLOG_H */
