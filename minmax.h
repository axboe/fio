#ifndef FIO_MIN_MAX_H
#define FIO_MIN_MAX_H

#ifndef min
#define min(x,y) ({ \
	__typeof__(x) _x = (x);	\
	__typeof__(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })
#endif

#ifndef max
#define max(x,y) ({ \
	__typeof__(x) _x = (x);	\
	__typeof__(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })
#endif

#define min_not_zero(x, y) ({		\
	__typeof__(x) __x = (x);		\
	__typeof__(y) __y = (y);		\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })

#endif
