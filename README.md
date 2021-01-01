# relobfuscate

ELF binary obfuscation tool using relocation.

Currently works only for ELF x86-64 64-bit binaries.

## What is it?

relobfuscate is a tool that can obfuscate binaries by adding malcrafted relocations.
The tool doesn't injects any single byte of code into the binary, which could confuse
the reversers.

It works fine without source code, but works better with source code since the tool needs
to touch less things.

The tool can be used to make so data in the binary file gets camouflauged as another data,
while remaining the original bytes at execution. It can also make so the data becomes
different from original at execution.

For example if you have a program that just prints string `hello`,
then you can use the tool to obfuscate the string to appear as `12345`
in static analyses (e.g. strings) but still printing `hello`.
It can also do the opposite, still showing `hello` in static
analyses but printing `12345` at execution.

A shitty designed script language is used to specify the memory addresses to obfuscate.

## How does it work?

The relocation table contains a list of relocations to resolve,
it could be symbols to resolve at runtime or on demand, this tool adds relocations that will
be resolved at runtime.

The relocation consists of three parts:
 * Offset: specified in RVA, tells where in the memory to write the resolved value.
 * Info: contains the id of symbol to use, and what relocation type it has.
 * Addend: a value to add to the resolved value before writing to the memory.

It uses the determinitic parts in a resolved symbol value to write
arbitrary value in the memory at runtime. When an address of a symbol gets resolved,
the value will look random due to ASLR but first 12 bits are deterministic because the
randomization is done at page level, and not at byte level. \
Combining this with addend in relocation, which adds the addend value to resolved value,
it makes it possible to write arbitrary values to the memory by constructing relocations
so they write byte to byte sequentially.

It has a side effect that it will corrupt 7 bytes, the non-deterministic parts of
symbol resolve, but this can be avoided by resolving symbol sizes instead of addresses.
A size of a symbol is (usually) deterministic and (probably) never changes per execution
or environment.

## Detection

The tool comes with a shitty detection feature.

### How this tool detects

The tool look for 3 things:
 * Alignment \
It checks that all the relocation writes to 8 byte aligned memory addresses. \
Writes to unaligned memory addresses seemed to not occur at all,
at least in none of the binaries in the authors computer.
 * Intersection \
Obviously if two relocation intersects where it writes, it must be relobfuscated since
there are no legitimate reason to do that in a normal binary.
 * Relocation type \
A binary with `R_X86_64_SIZE32` or `R_X86_64_SIZE64` gets warned as potentially relobfuscated,
because really few seems to actually use that relocation type.

### Theoretical ways to detect

One way to detect relobfuscation could be to compare the segment/dynamic information with
section headers to find unmatching part.

Other way could be to check where the relocation writes will be done, and make sure that 
it doesn't write to weird place where it should never happen (e.g. in the elf header).
Though this has a limitation since the data/text section is most only the interesting
part to obfuscate, which cannot (or at least difficult to) be detected with this method.
Writes to text section could be flagged as relobfuscated,
but ELF has a flag called `DF_TEXTREL` which allows to write resolved values to text section,
and kinda says that it is a feature to be able to do that.

## Build

Just run ```make```, if it succeeded you should see `relobfuscate`.

To build it you need to install:
 * `bison`
 * `flex`
 * `gcc`

## Usage

### Obfuscate a binary

Obfuscate `binary` using relocation script `binary.rlc` and save as `binary.obf`:

`relobfuscate -i binary -o binary.obf -s binary.rlc`

### Source integration

First generate relocation c file `binary_reloc.c` from `binary.rlc`:

`relobfuscate -c binary_reloc.c -s binary.rlc`

You will probably have to manually add `#include <...>` in the generated c file so it
doesn't get errors when compilnig.
Then compile this c file together with your code:

`gcc -o binary binary_reloc.c ...`

And then use relobfuscate with `-r` flag:

`relobfuscate -r -i binary -o binary.obf -s binary.rlc`

`-r` flag will replace the `binary_reloc.c` populated relocations according to `binary.rlc`.

### Detect a relobfuscated binary

Check if `binary` is relobfuscated.

`relobfuscate -d binary`

## Relocation script format

### Specifiy relocation to use:
```<RELOCATION TYPE> [-overwrite] [-dirty]```  
```<RELOCATION TYPE> <SYMBOL> <SYMBOL VALUE> [-overwrite] [-dirty]```

#### Relocation types
 * ```SIZE8|SIZE16|SIZE24|SIZE32```  
Uses `R_X86_64_SIZE32` (4 bytes) to write 1-4 bytes per relocation. \
The symbol value should be the size of the dynamic symbol. \
3-0 bytes will get corrupted if dirty flag is specified.
 * ```SIZE40|SIZE48|SIZE56|SIZE64```  
Uses `R_X86_64_SIZE64` (8 bytes) to write 5-8 bytes per relocation. \
The symbol value should be the size of the dynamic symbol. \
3-0 bytes will get corrupted if dirty flag is specified.
 * ```ADDR8```  
Uses `R_X86_64_64` (8 bytes) to write 1 byte per relocation. \
Using a dynamic symbol from a library that may differ from system to system (e.g. libc)
will result in symbols getting resolved to different values depending on the library version. \
The symbol value should be the least significant byte of the address of the dynamic symbol. \
7 bytes will get corrupted since they have non-deterministic values.
 * ```REL8```  
Uses `R_X86_64_RELATIVE` (8 bytes) to write 1 byte per relocation. \
Probably doesn't matter what symbol to use, and recommended to not specify a symbol
when using this since that's how it is usually used. \
Ignores symbol value. \
7 bytes will get corrupted since they have non-deterministic values.

Using a relocation type that writes many bytes at once (e.g. `SIZE64`) 
will result in fewer relocations, but results in larger fragments
that could be observed by tools like `strings`.

#### Symbol

The name of a dynamic symbol, the symbol must be available in one of the libraries
that the target binary uses. If not specified it will use null symbol,
which seems to always resolve to base address for address relocation types,
and 0 for size relocation types.

Specifying incorrect symbol value will result in incorrect bytes written to the memory.

#### Flags
 * `-overwrite`  
The specified memory values will be written at runtime. \
If not specified the memory values will be appearing in the file and original bytes gets recovered at runtime.
 * `-dirty`  
If specified it will ignore to recover bytes that gets corrupted by the relocations. \
This flag is forced for all relocation types except `SIZE8|...|SIZE64`.

#### Examples

 * ```SIZE8 optind 4```  
Use relocation type `R_X86_64_SIZE32` with symbol `optind`, which has byte size 4,
to write 1 byte per relocation. \
The writes will be seen in the file, and original bytes gets recovered at runtime.
 * ```SIZE16 optind 4 -overwrite```  
Use relocation type `R_X86_64_SIZE32` with symbol `optind`, which has byte size 4,
to write 2 byte per relocation. \
The writes will be seen at runtime, and original bytes are still visible in the file. 
 * ```SIZE56 optind 4 -dirty```  
Use relocation type `R_X86_64_SIZE64` with symbol `optind`, which has byte size 4,
to write 7 byte per relocation. \
The writes will be seen in the file, and original bytes gets recovered at runtime. \
The last relocation in a sequence will corrupt 1 bytes.
 * ```ADDR8 printf 4 -overwrite```  
Use relocation type `R_X86_64_64` with symbol `optind`, which has byte size 4,
to write 1 byte per relocation. \
The writes will be seen at runtime, and original bytes are still visible in the file. \
The last relocation in a sequence will corrupt 7 bytes.
 * ```REL8 -overwrite```  
Use relocation type `R_X86_64_RELATIVE` with null symbol to write 1 byte per relocation. \
The writes will be seen at runtime, and original bytes are still visible in the file. \
The last relocation in a sequence will corrupt 7 bytes.
 

### Memory writes
```<ADDRESS>: <VALUES>```

#### Examples
 * ```0x201000: "hello\x00"```  
Writes `hello\x00` at `base_address + 0x201000`,
note that strings do not automatically include null bytes and needs to be explicitly written.
 * ```symbol_name: | 61 62 63 00 |```  
Writes `abc\x00` at `symbol_name`.
 * ```symbol_name+5: "ola\namigos" | 61 62 63 00 |```  
Writes `ola\namigosabc\x00` at `symbol_name + 5`.
 * ```0x201000: symbol_name+3```  
Writes RVA (8 bytes) of `symbol_name + 3` to address `base_address + 0x201000`. \
Pretty useless in most cases.

## Examples

All the examples are compiled with `-nostartfiles` flag to use `_start` instead of `main`. 
This was done to make it easier to analyze for users.

### Build examples

Just run ```make example```.

### hello

This example prints four string variables: `a`, `b`, `c` and `d`.

And these gets altered by the tool:
 * `a` is still `hello` in the execution, but `strings` will show `help` instead.
 * `b` is `bye bye` in the execution, but `strings` still shows `world`.
 * `c` is pretty much same as `b` but uses dynamic symbol to write the values.
 * `d` is also pretty much same as `b` and `c`, but shows side effects of dirty flag.

`a` demonstrates way to hide the original value so it's only visible at runtime, 
while `b` (which uses overwrite flag) demonstrates way to write hidden value so it's only visible at runtime

Read `example/hello/hello.rlc` for more details.

### shell

This example overwrites code section with a shellcode that calls `/bin/ls`.

The original program just prints `nothing special` and exits, 
but the obfuscated binary will execute the aforementioned shellcode.

`objdump` and other tools will still show the original code, and not the shellcode.

Read `example/shell/shell.rlc` for more details.

### libcrypt

This example makes use of symbol resolve so the library works as a decryption key.

Due to that the libraries provide same symbols, but have different page offset for them,
the relocations will write different values depending on which library being used. So
it works as if the libraries are decryption keys.

The relobfuscated program resolves symbols from `key.so` (symlink that points to `key1.so`),
relinking the `key.so` to link at `key2.so` will result in the
program to print different message.

Neither libraries contain any strings nor code, just symbols with with
specific offset in a page.

For scrubs: `ln -sf key2.so key.so`

(You need to enter the directory because otherwise it can't find the library `key.so`)

### edit_rela

This example uses a relocation to repoint the next relocation offset to code section, 
and the second (the one that gets overwritten) writes infinity loop instruction to code section.

Running the obfuscated program will just result in doing nothing but infinity loop.

Read `example/edit_rela/edit_rela.rlc` for more details.

## Idea

### Overwrite ELF structures

Rewriting EHDR, PHDR and dynamic section did not seem to work (nothing seemed to happen).
At least relocation table works to rewrite as seen in the example. Maybe some interesting
stuff could be done with rewriting symbol names?

## Bug?

Running `ldd` command on obfuscated binaries will tell that the binary is not a
dynamic executable (it still works totally fine to run the obfuscated binary).
The reason this happens is not really clear. \
For some reason the issue can be fixed by using second segment (data segment) to expand
by specifying `-p 1` flag in relobfuscate.

## Note

A PoC of obfuscation using relocation table was done by [ulexec](https://github.com/ulexec/elf_rela_obfuscation) before me.
