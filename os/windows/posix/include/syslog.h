#ifndef SYSLOG_H
#define SYSLOG_H

int syslog();

#define LOG_INFO 0
#define LOG_ERROR 1
#define LOG_WARN 2

#define LOG_NDELAY 0
#define LOG_NOWAIT 0
#define LOG_PID 0
#define LOG_USER 0

void closelog(void);
void openlog(const char *ident, int logopt, int facility);

#endif /* SYSLOG_H */
