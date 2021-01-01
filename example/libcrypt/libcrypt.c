#include <stdio.h>
#include <stdlib.h>

char s[64] = "\"yo\" - program, 2021";

void _start()
{
	printf("%s\n", s);

	// needed to add key.so as dependency
	extern int *asdf;
	asdf = 0;

	exit(0);
}
