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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <string.h>
#include "y.tab.h"

#define YYSTYPE PARSER_VALUE_TYPE

extern int lexer_input(char* buffer, int *nbytes, int buffersize);

#undef YY_INPUT
#define YY_INPUT(buffer, bytes_read, bytes_requested) \
		lexer_input((buffer), &(bytes_read), (bytes_requested))

extern int yyerror(long long *result, double *dresult,
		int *has_error, int *bye, const char *msg);

static void __attribute__((unused)) yyunput(int c,char *buf_ptr);
static int __attribute__((unused)) input(void);

%}

%%


bye	return BYE;
[ \t] ; /* ignore whitespace */
#.+ ; /* ignore comments */
[0-9]*[.][0-9]+ {
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
[+-/*()]	return yytext[0];
.	{
		yylval.v.has_error = 1;
		return NUMBER;	
	}
%%

