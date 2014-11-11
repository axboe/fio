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
#include <math.h>

struct parser_value_type {
	double dval;
	long long ival;
	int has_dval;
	int has_error;
};

typedef union valtype {
	struct parser_value_type v;
} PARSER_VALUE_TYPE;

#define YYSTYPE PARSER_VALUE_TYPE

int yyerror(__attribute__((unused)) long long *result,
		__attribute__((unused)) double *dresult,
		__attribute__((unused)) int *has_error,
		__attribute__((unused)) int *units_specified,
		__attribute__((unused)) const char *msg);

extern int yylex(void);
extern void yyrestart(FILE *file);
extern int lexer_value_is_time;

%}

%union valtype {
	struct parser_value_type {
		double dval;
		long long ival;
		int has_dval;
		int has_error;
	} v;
};

%token <v> NUMBER
%token <v> BYE
%token <v> SUFFIX 
%left '-' '+'
%right SUFFIX
%left '*' '/'
%right '^'
%left '%'
%nonassoc UMINUS
%parse-param { long long *result }
%parse-param { double *dresult }
%parse-param { int *has_error }
%parse-param { int *units_specified }

%type <v> expression
%%

top_level:	expression {
				*result = $1.ival;
				*dresult = $1.dval;
				*has_error = $1.has_error;
			}
		| expression error {
				*result = $1.ival;
				*dresult = $1.dval;
				*has_error = 1;
			}
expression:	expression '+' expression { 
			if (!$1.has_dval && !$3.has_dval)
				$$.ival = $1.ival + $3.ival;
			else
				$$.ival = (long long) ($1.dval + $3.dval);
			$$.dval = $1.dval + $3.dval;
			$$.has_error = $1.has_error || $3.has_error;
		}
	|	expression '-' expression {
			if (!$1.has_dval && !$3.has_dval)
				$$.ival = $1.ival - $3.ival; 
			else
				$$.ival = (long long) ($1.dval - $3.dval); 
			$$.dval = $1.dval - $3.dval; 
			$$.has_error = $1.has_error || $3.has_error;
		}
	|	expression '*' expression {
			if (!$1.has_dval && !$3.has_dval)
				$$.ival = $1.ival * $3.ival;
			else
				$$.ival = (long long) ($1.dval * $3.dval);
			$$.dval = $1.dval * $3.dval;
			$$.has_error = $1.has_error || $3.has_error;
		}
	|	expression '/' expression {
			if ($3.ival == 0)
				yyerror(0, 0, 0, 0, "divide by zero");
			else
				$$.ival = $1.ival / $3.ival;
			if ($3.dval < 1e-20 && $3.dval > -1e-20)
				yyerror(0, 0, 0, 0, "divide by zero");
			else
				$$.dval = $1.dval / $3.dval;
			if ($3.has_dval || $1.has_dval)
				$$.ival = (long long) $$.dval;
			$$.has_error = $1.has_error || $3.has_error;
		}
	|	'-' expression %prec UMINUS {
			$$.ival = -$2.ival;
			$$.dval = -$2.dval;
			$$.has_error = $2.has_error;
		}
	|	'(' expression ')' { $$ = $2; }
	|	expression SUFFIX {
			if (!$1.has_dval && !$2.has_dval)
				$$.ival = $1.ival * $2.ival;
			else
				$$.ival = (long long) $1.dval * $2.dval;
			if ($1.has_dval || $2.has_dval)
				$$.dval = $1.dval * $2.dval;
			else
				$$.dval = $1.ival * $2.ival;
			$$.has_error = $1.has_error || $2.has_error;
			*units_specified = 1;
		}
	|	expression '%' expression {
			if ($1.has_dval || $3.has_dval)
				yyerror(0, 0, 0, 0, "modulo on floats");
			if ($3.ival == 0)
				yyerror(0, 0, 0, 0, "divide by zero");
			else {
				$$.ival = $1.ival % $3.ival;
				$$.dval = $$.ival;
			}
			$$.has_error = $1.has_error || $3.has_error;
		}
	|	expression '^' expression {
			$$.has_error = $1.has_error || $3.has_error;
			if (!$1.has_dval && !$3.has_dval) {
				int i;

				if ($3.ival == 0) {
					$$.ival = 1;
				} else if ($3.ival > 0) {
					long long tmp = $1.ival;
					$$.ival = 1.0;
					for (i = 0; i < $3.ival; i++)
						$$.ival *= tmp;
				}  else {
					/* integers, 2^-3, ok, we now have doubles */
					double tmp;
					if ($1.ival == 0 && $3.ival == 0) {
						tmp = 1.0;
						$$.has_error = 1;
					} else {
						double x = (double) $1.ival;
						double y = (double) $3.ival;
						tmp = pow(x, y);
					}
					$$.ival = (long long) tmp;
				}
				$$.dval = pow($1.dval, $3.dval);
			} else {
				$$.dval = pow($1.dval, $3.dval);
				$$.ival = (long long) $$.dval;
			}
		}
	|	NUMBER { $$ = $1; };
%%
#include <stdio.h>

/* Urgh.  yacc and lex are kind of horrible.  This is not thread safe, obviously. */
static int lexer_read_offset = 0;
static char lexer_input_buffer[1000];

int lexer_input(char* buffer, unsigned int *bytes_read, int bytes_requested)
{
	int bytes_left = strlen(lexer_input_buffer) - lexer_read_offset;

	if (bytes_requested > bytes_left )
		bytes_requested = bytes_left;
	memcpy(buffer, &lexer_input_buffer[lexer_read_offset], bytes_requested);
	*bytes_read = bytes_requested;
	lexer_read_offset += bytes_requested;
	return 0;
}

static void setup_to_parse_string(const char *string)
{
	unsigned int len;

	len = strlen(string);
	if (len > sizeof(lexer_input_buffer) - 3)
		len = sizeof(lexer_input_buffer) - 3;

	strncpy(lexer_input_buffer, string, len);
	lexer_input_buffer[len] = '\0'; 
	lexer_input_buffer[len + 1] = '\0';  /* lex/yacc want string double null terminated! */
	lexer_read_offset = 0;
}

int evaluate_arithmetic_expression(const char *buffer, long long *ival, double *dval,
					double implied_units, int is_time)
{
	int rc, units_specified = 0, has_error = 0;

	lexer_value_is_time = is_time;
	setup_to_parse_string(buffer);
	rc = yyparse(ival, dval, &has_error, &units_specified);
	yyrestart(NULL);
	if (rc || has_error) {
		*ival = 0;
		*dval = 0;
		has_error = 1;
	}
	if (!units_specified) {
		*ival = (int) ((double) *ival * implied_units);
		*dval = *dval * implied_units;
	}
	return has_error;
}

int yyerror(__attribute__((unused)) long long *result,
		__attribute__((unused)) double *dresult,
		__attribute__((unused)) int *has_error,
		__attribute__((unused)) int *units_specified,
		__attribute__((unused)) const char *msg)
{
	/* We do not need to do anything here. */
	return 0;
}

