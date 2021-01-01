PROGRAM := ./relobfuscate

CC := gcc
CFLAGS := -Wall -fsanitize=address -ggdb
LDFLAGS := -lasan


.PHONY: program all example clean

program: $(PROGRAM)

all: program example

example: $(PROGRAM) example/hello/hello.obf example/shell/shell.obf example/libcrypt/libcrypt.obf example/edit_rela/edit_rela.obf


$(PROGRAM): src/*.c src/parser/script.tab.c src/parser/lex.yy.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/parser/script.tab.c: src/parser/script.y
	bison -d -b src/parser/script --report=state src/parser/script.y

src/parser/lex.yy.c: src/parser/script.lex src/parser/script.tab.c
	flex -o $@ src/parser/script.lex


example/hello/hello: example/hello/hello.c
	$(CC) -o $@ $^ -nostartfiles

example/hello/hello.obf: example/hello/hello example/hello/hello.rlc
	$(PROGRAM) -i $< -o $@ -s $(word 2,$^)

example/shell/shell: example/shell/shell.c
	$(CC) -o $@ $^ -nostartfiles

example/shell/shell.obf: example/shell/shell example/shell/shell.rlc
	$(PROGRAM) -i $< -o $@ -s $(word 2,$^)

example/libcrypt/libcrypt: example/libcrypt/libcrypt.c example/libcrypt/keys.py
	python3 example/libcrypt/keys.py
	$(CC) -o example/libcrypt/key1.so example/libcrypt/key1.s -shared -nostartfiles
	$(CC) -o example/libcrypt/key2.so example/libcrypt/key2.s -shared -nostartfiles
	ln -sf key1.so example/libcrypt/key.so
	(cd example/libcrypt/; $(CC) -o libcrypt libcrypt.c ./key.so -nostartfiles)

example/libcrypt/libcrypt.obf: example/libcrypt/libcrypt example/libcrypt/libcrypt.rlc
	$(PROGRAM) -i $< -o $@ -s $(word 2, $^)

example/edit_rela/relocs.c: example/edit_rela/edit_rela.rlc
	$(PROGRAM) -n -c $@ -s $^
	sed -i '1s/^/#include <getopt.h>\n/' $@

example/edit_rela/edit_rela: example/edit_rela/edit_rela.c example/edit_rela/relocs.c
	$(CC) -o $@ $^ -nostartfiles

example/edit_rela/edit_rela.obf: example/edit_rela/edit_rela example/edit_rela/edit_rela.rlc
	$(PROGRAM) -n -r -i $< -o $@ -s $(word 2,$^)


clean:
	rm -f $(PROGRAM) src/parser/script.tab.* src/parser/lex.yy.c src/parser/script.output
