#ifndef FIO_ASPRINTF_H
#define FIO_ASPRINTF_H

#ifndef CONFIG_HAVE_VASPRINTF
int vasprintf(char **strp, const char *fmt, va_list ap);
#endif
#ifndef CONFIG_HAVE_ASPRINTF
int asprintf(char **strp, const char *fmt, ...);
#endif

#endif /* FIO_ASPRINTF_H */
