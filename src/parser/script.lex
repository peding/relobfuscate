%{

#include <stdio.h>
#include <elf.h>
#include "script.tab.h"

%}

%option noyywrap nounput noinput

%x HEX STRING

%%

SIZE(8|16|24|32)				{ yylval.reloc_type_val = (reloc_type){R_X86_64_SIZE32, atoi(yytext+4)/8}; return RELOC_TYPE; }
SIZE(40|48|56|64)				{ yylval.reloc_type_val = (reloc_type){R_X86_64_SIZE64, atoi(yytext+4)/8}; return RELOC_TYPE; }
ADDR8							{ yylval.reloc_type_val = (reloc_type){R_X86_64_64, 1}; return RELOC_TYPE; }
REL8							{ yylval.reloc_type_val = (reloc_type){R_X86_64_RELATIVE, 1}; return RELOC_TYPE; }

-overwrite						{ return OVERWRITE; }
-dirty							{ return DIRTY; }

[_a-zA-Z][_a-zA-Z0-9]*			{ yylval.str_val = strdup(yytext); return SYMBOL; }
\.[_a-zA-Z][\._a-zA-Z0-9]*		{ yylval.str_val = strdup(yytext); return SECTION; }
[0-9]+							{ yylval.int_val = strtoll(yytext, NULL, 10); return NUM; }
0x[0-9a-fA-F]+					{ yylval.int_val = strtoll(yytext+2, NULL, 16); return NUM; }
\+								{ return PLUS; }
\-								{ return MINUS; }
:								{ return COLON; }

\|								{ BEGIN(HEX); }
<HEX>\|							{ BEGIN(INITIAL); }
<HEX>[0-9a-fA-F]{2}				{ yylval.int_val = strtoll(yytext, NULL, 16); return BYTE; }

\"								{ BEGIN(STRING); }
<STRING>\"						{ BEGIN(INITIAL); }
<STRING>\\x[0-9a-fA-F]{2}		{ yylval.int_val = strtoll(yytext+2, NULL, 16); return BYTE; }
<STRING>\\n						{ yylval.int_val = '\n'; return BYTE; }
<STRING>\\.						{ yylval.int_val = yytext[1]; return BYTE; }
<STRING>[^"]					{ yylval.int_val = *yytext; return BYTE; }

<*>\#.*[^\n]					{ }
<*>[ ]+							{ }
<*>[\n]							{ BEGIN(INITIAL); yylineno++; return NEWLINE; }

<*>.							{ return SHIT; }

%%
