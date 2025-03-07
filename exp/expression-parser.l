%{

/*
 * (C) Copyright 2014, Stephen M. Cameron.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <string.h>
#include "y.tab.h"

#define YYSTYPE PARSER_VALUE_TYPE

extern int lexer_input(char *buffer, unsigned int *nbytes, int buffersize);

#undef YY_INPUT
#define YY_INPUT(buffer, bytes_read, bytes_requested)			\
({									\
	int __ret;							\
	unsigned int __bread = bytes_read;				\
	__ret = lexer_input((buffer), &__bread, (bytes_requested));	\
	bytes_read = __bread;						\
	__ret;								\
})

extern int yyerror(long long *result, double *dresult,
		int *has_error, int *units_specified, const char *msg);

static void __attribute__((unused)) yyunput(int c, char *buf_ptr);
static int __attribute__((unused)) input(void);

/* set by parser -- this is another thing which makes the parser thread-unsafe :(. */
int lexer_value_is_time = 0; /* for determining if "m" suffix means mega- or minutes */

#define set_suffix_value(yylval, i_val, d_val, has_d_val) \
	(yylval).v.dval = (d_val); \
	(yylval).v.ival = (i_val); \
	(yylval).v.has_dval = (has_d_val); \
	(yylval).v.has_error = 0;

%}

%%


[kK]|[kK][bB] 	{
			set_suffix_value(yylval, 1024, 1024.0, 0);
			return SUFFIX;
		}
[Mm][bB]	{
			set_suffix_value(yylval, 1024 * 1024, 1024.0 * 1024.0, 0);
			return SUFFIX;
		}
[mM][sS]	{
			set_suffix_value(yylval, 1000, 1000.0, 1);
			return SUFFIX;
		}
[uU][sS]	{
			set_suffix_value(yylval, 1, 1.0, 1);
			return SUFFIX;
		}
[gG]|[Gg][Bb]	{
			set_suffix_value(yylval, 1024LL * 1024 * 1024, 1024.0 * 1024.0 * 1024, 0);
			return SUFFIX;
		}
[tT]|[tT][bB]	{	
			set_suffix_value(yylval, 1024LL * 1024 * 1024 * 1024,
						1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024, 0);
			return SUFFIX;
		}
[pP]|[pP][bB]	{	
			set_suffix_value(yylval, 1024LL * 1024 * 1024 * 1024 * 1024,
					1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0, 0);
			return SUFFIX;
		}
[kK][iI][Bb]	{
			set_suffix_value(yylval, 1000LL, 1000.0, 0);
			return SUFFIX;
		}
[mM][Ii][bB]	{
			set_suffix_value(yylval, 1000000LL, 1000000.0 , 0);
			return SUFFIX;
		}
[gG][iI][Bb]	{
			set_suffix_value(yylval, 1000000000LL, 1000000000.0 , 0);
			return SUFFIX;
		}
[pP][iI][Bb]	{	
			set_suffix_value(yylval, 1000000000000LL, 1000000000000.0 , 0);
			return SUFFIX;
		}
[sS]		{
			set_suffix_value(yylval, 1000000LL, 1000000.0 , 0);
			return SUFFIX;
		}
[mM]		{
			if (!lexer_value_is_time) {
				set_suffix_value(yylval, 1024 * 1024, 1024.0 * 1024.0, 0);
			} else {
				set_suffix_value(yylval, 60LL * 1000000LL, 60.0 * 1000000.0, 0);
			}
			return SUFFIX;
		}
[dD]		{
			set_suffix_value(yylval, 60LL * 60LL * 24LL * 1000000LL,
						60.0 * 60.0 * 24.0 * 1000000.0, 0);
			return SUFFIX;
		}
[hH]		{	
			set_suffix_value(yylval, 60LL * 60LL * 1000000LL,
					60.0 * 60.0 * 1000000.0, 0);
			return SUFFIX;
		}
[ \t] ; /* ignore whitespace */
[#:,].* ; /* ignore comments, and everything after colons and commas */
[0-9]*[.][0-9]+|[0-9]*[.]?[0-9]+[eE][-+]*[0-9]+ {
			int rc;
			double dval;

			rc = sscanf(yytext, "%lf", &dval);
			if (rc == 1) {
				yylval.v.dval = dval;
				yylval.v.ival = (long long) dval;
				yylval.v.has_dval = 1;
				yylval.v.has_error = 0;
				return NUMBER;
			} else {
				yyerror(0, 0, 0, 0, "bad number\n");
				yylval.v.has_error = 1;
				return NUMBER;
			}
		}
0x[0-9a-fA-F]+ {
		int rc, intval;
		rc = sscanf(yytext, "%x", &intval);
		if (rc == 1) {
			yylval.v.ival = intval;
			yylval.v.dval = (double) intval;
			yylval.v.has_dval = 0;
			yylval.v.has_error = 0;
			return NUMBER;
		} else {
			yyerror(0, 0, 0, 0, "bad number\n");
			yylval.v.has_error = 1;
			return NUMBER;
		}
	}
[0-9]+	{
		int rc, intval;
		rc = sscanf(yytext, "%d", &intval);
		if (rc == 1) {
			yylval.v.ival = intval;
			yylval.v.dval = (double) intval;
			yylval.v.has_dval = 0;
			yylval.v.has_error = 0;
			return NUMBER;
		} else {
			yyerror(0, 0, 0, 0, "bad number\n");
			yylval.v.has_error = 1;
			return NUMBER;
		}
	}
\n	return 0;
[+-/*()^%]	return yytext[0];

.	{
		yylval.v.has_error = 1;
		return NUMBER;	
	}
%%

