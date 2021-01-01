%{

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <elf.h>

void yyerror(char *s);
int yylex();

typedef struct _memory memory;

extern FILE *yyin;

extern bool mem_sort;

extern memory ***memories;
extern int *memories_count;

#define HAS_RELOC \
	if (reloc.size == 0) { \
		yyerror("relocation type not set"); \
		YYABORT; \
	}

%}

%code requires {


#include "../elfer.h"

extern const elf_bin *sym_bin;

typedef struct _reloc_type {
	int type;
	int size;
	uint64_t addend;
	bool overwrite;
	bool dirty;
	char *name;
} reloc_type;

typedef struct _memory {
	uint64_t addr;
	uint64_t size;
	uint64_t buffer_size;
	uint8_t *values;

	reloc_type reloc;
} memory;

extern reloc_type reloc;

memory *init_memory(uint8_t byte);
void memory_append(memory *mem, uint8_t byte);
int cmp_memories(const void *a, const void *b);

int cmp_str(void const *a, void const *b);
char **memories_symbol_names(memory **mods, int mod_count, int *count);
void free_symbol_names(char **names, int count);

bool read_reloc_script(const char *filename, const elf_bin * bin, bool sort, memory ***mods, int *mod_count);
void free_memories(memory **mods, int mod_count);
}

%union {
	uint64_t int_val;
	char *str_val;
	reloc_type reloc_type_val;
	memory *mem_val;
}

%start script

%token NEWLINE COLON PLUS MINUS OVERWRITE DIRTY SHIT

%token <int_val> BYTE NUM;
%token <str_val> SYMBOL SECTION;
%token <reloc_type_val> RELOC_TYPE;

%type <mem_val> modify values;
%type <int_val> addr addr_expr;

%%

script:	lines							{ free(reloc.name); if (mem_sort) { qsort(*memories, *memories_count, sizeof(memory *), cmp_memories); } }

lines:	line
		| lines NEWLINE line
		;

line:
		| type
		| modify						{ *memories = realloc(*memories, (++(*memories_count)) * sizeof(memory *)); (*memories)[*memories_count-1] = $1; }
		;

type:	RELOC_TYPE SYMBOL NUM			{ free(reloc.name); reloc.type = $1.type; reloc.size = $1.size; reloc.name = strdup($2); free($2); reloc.addend = $3; reloc.overwrite = reloc.dirty = false; }
		| RELOC_TYPE SYMBOL NUM flags	{ free(reloc.name); reloc.type = $1.type; reloc.size = $1.size; reloc.name = strdup($2); free($2); reloc.addend = $3; }
		| RELOC_TYPE					{ free(reloc.name); reloc.type = $1.type; reloc.size = $1.size; reloc.name = strdup(""); reloc.addend = 0; reloc.overwrite = reloc.dirty = false; }
		| RELOC_TYPE flags				{ free(reloc.name); reloc.type = $1.type; reloc.size = $1.size; reloc.name = strdup(""); reloc.addend = 0; }
		;

flags:	flag
		| flags flag
		;

flag:	OVERWRITE						{ reloc.overwrite = true; }
		| DIRTY							{ reloc.dirty = true; }
		;

modify: addr_expr COLON values			{ $3->addr = $1; $$ = $3; }
		;

addr_expr:	addr						{ $$ = $1; }
			| addr PLUS NUM				{ $$ = $1 + $3; }
			| addr MINUS NUM			{ $$ = $1 - $3; }
			;

addr:	NUM								{ HAS_RELOC; $$ = $1; }
		| SYMBOL						{ HAS_RELOC; if (sym_bin) { Elf64_Sym *s = get_symbol(sym_bin, $1, false); if (s) $$ = s->st_value; else { yyerror("symbol not found"); YYABORT; }} else { $$ = 0; } free($1); }
		| SECTION						{ HAS_RELOC; if (sym_bin) { Elf64_Shdr *sh = get_section_header(sym_bin, $1); if (sh) $$ = sh->sh_addr; else { yyerror("section not found"); YYABORT; }} else { $$ = 0; } free($1); }
		;

values:	BYTE							{ $$ = init_memory($1); }
		| addr_expr						{ $$ = init_memory($1 & 0xff); for (int i = 1; i < 8; i++) { memory_append($$, ($1 >> (8 * i)) & 0xff); } }
		| values BYTE					{ memory_append($1, $2); $$ = $1; }
		| values addr_expr				{ $$ = $1; for (int i = 0; i < 8; i++) { memory_append($$, ($2 >> (8 * i)) & 0xff); } }
		;

%%

const elf_bin *sym_bin = 0;
reloc_type reloc = {R_X86_64_SIZE32, 0};
bool mem_sort = true;

memory ***memories = 0;
int *memories_count = 0;

// take a byte and create a memory structure
memory *init_memory(uint8_t byte)
{
	memory *mem = malloc(sizeof(memory));

	// init memory stuff
	mem->addr = 0;
	mem->buffer_size = 8;
	mem->size = 1;
	mem->values = malloc(mem->buffer_size);

	// set first byte
	mem->values[0] = byte;

	// init relocation stuff
	mem->reloc = reloc;
	mem->reloc.name = strdup(reloc.name);

	return mem;
}

// append a byte to memory structure
void memory_append(memory *mem, uint8_t byte)
{
	// expand memory size if it's full
	if (mem->size == mem->buffer_size) {
		mem->buffer_size *= 2;
		mem->values = realloc(mem->values, mem->buffer_size);
	}

	mem->values[mem->size] = byte;

	mem->size++;
}

// compare two address in memory structures, used for qsort
int cmp_memories(const void *a, const void *b)
{
	return (*(memory **)a)->addr - (*(memory **)b)->addr;
}

// compare two string, used for qsort
int cmp_str(void const *a, void const *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

// return all symbol names in the memory structures, no duplicates
char **memories_symbol_names(memory **mods, int mod_count, int *count)
{
	char **names = malloc(mod_count * sizeof(char *));

	// copy symbol names
	for (int i = 0; i < mod_count; i++) {
		names[i] = strdup(mods[i]->reloc.name);
	}

	// sort the names to make it easy to find duplicates
	qsort(names, mod_count, sizeof(char *), (int (*)(const void *, const void *))cmp_str);

	// find duplicates and remove them
	*count = mod_count;
	for (int i = mod_count - 1; i > 0; i--) {
		if (!strcmp(names[i-1], names[i])) {
			(*count)--;
			free(names[i]);
			memmove(&names[i], &names[i+1], (mod_count - 1 - i) * sizeof(char *));
		}
	}

	// resize the array to minimum size and return
	return realloc(names, *count * sizeof(char *));
}

// free symbol names
void free_symbol_names(char **names, int count)
{
	for (int i = 0; i < count; i++)
		free(names[i]);
	free(names);
}

// print parse error
void yyerror(char *s)
{
	extern int yylineno;

	fprintf(stderr, "error: %s at line %d\n", s, yylineno);
}

// read a relocation script and creates memory structure
// a binary file can be passed to allow the parser to resolve symbols referenses for address
bool read_reloc_script(const char *filename, const elf_bin * bin, bool sort, memory ***mods, int *mod_count)
{
	// open relocation script
	FILE *script = fopen(filename, "r");
	if (!script) {
		fprintf(stderr, "error: failed to open file: %s\n", filename);
		exit(1);
	}

	// init parser stuff
	sym_bin = bin;
	reloc = (reloc_type){R_X86_64_SIZE32, 0};
	mem_sort = sort;

	memories = mods;
	*memories = 0;
	memories_count = mod_count;
	*memories_count = 0;

	yyin = script;
	// start parsing script
	bool success = !yyparse();

	fclose(script);

	return success;
}

// free a memory structure
void free_memories(memory **mods, int mod_count)
{
	for (int i = 0; i < mod_count; i++) {
		free(mods[i]->reloc.name);
		free(mods[i]->values);
		free(mods[i]);
	}

	free(mods);
}
