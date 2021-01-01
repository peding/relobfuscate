#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <stdbool.h>
#include <unistd.h>

#include "elfer.h"
#include "parser/script.tab.h"

// print useless help
void help(const char *path)
{
	printf("obfuscate:\n\t%s [-rnv] [-p id] -i <input-binary> -o <output-binary> -s <relocation-script>\n\n", path);
	printf("\t-r\treplace instead of injecting relocations (binary required to be linked with relocation c file)\n");
	printf("\t-n\tdon't sort the relocation writes by addresses\n");
	printf("\t-v\tdelete DT_VERSYM, DT_VERNEED DT_VERNEEDNUM\n");
	printf("\t-p id\tspecify segment to expand for injections\n\n");
	printf("generate relocation c file:\n\t%s [-n] -c <output-c-file> -s <relocation-script>\n\n", path);
	printf("\t-n\tdon't sort the relocation writes by addresses\n\n");
	printf("detect relobfuscated binary:\n\t%s -d <input-binary>\n\n", path);
}

// counts number of relocation required by the modifications
int required_relocs(memory **mods, int mod_count)
{
	int relocs_count = 0;
	for (int i = 0; i < mod_count; i++) {
		relocs_count += (mods[i]->size + (mods[i]->reloc.size - 1)) / mods[i]->reloc.size;
	}

	return relocs_count;
}

// check binary requirements for relobfuscation
bool check_elf_requirements(const elf_bin *bin)
{
	// make sure needed sections are available

	if (!bin->dynsym_shdr) {
		fprintf(stderr, "error: section .dynsym not found\n");
		return false;
	}
	if (!bin->dynstr_shdr) {
		fprintf(stderr, "error: section .dynstr not found\n");
		return false;
	}
	if (!bin->rela_dyn_shdr && !bin->rela_plt_shdr) {
		fprintf(stderr, "error: section .rela.dyn/.rela.plt not found\n");
		return false;
	}

	// if it uses .rela.plt then it must have BIND_NOW to work properly
	Elf64_Dyn *flags = get_tag(bin, DT_FLAGS);
	if ((!flags || !(flags->d_un.d_val & DF_BIND_NOW)) && !bin->rela_dyn_shdr) {
		fprintf(stderr, "warning: binary without BIND_NOW and .rela.dyn, probably won't work as intended\n");
	}

	return true;
}

// print memory modifications that will be performed
void print_memory_modifications(memory **mods, int mod_count)
{
	for (int i = 0; i < mod_count; i++) {
		printf("address: %lx (%ld bytes), symbol: %s", mods[i]->addr, mods[i]->size, mods[i]->reloc.name);
		if (mods[i]->reloc.overwrite || mods[i]->reloc.dirty) {
			printf(", flags: ");
			if (mods[i]->reloc.overwrite)
				printf("overwrite ");
			if (mods[i]->reloc.dirty)
				printf("dirty ");
		}
		printf("\n\t");

		for (int j = 0; j < mods[i]->size; j++)
			printf("%02x ", mods[i]->values[j]);
		printf("\n");
	}
}

// calculate the size a segment needs to be expanded
// it calculates the size for .dynstr/.dynsym (if required dynamic symbols are not available
// in the binary), .rela.dyn (or .rela.plt) and .gnu.version
uint64_t calculate_add_size(elf_bin *bin, int reloc_count, char **symbol_names, int symbol_count, uint64_t *add_dynstr_size, uint64_t *new_symbols)
{
	Elf64_Shdr *rela_shdr = (bin->rela_dyn_shdr ? bin->rela_dyn_shdr : bin->rela_plt_shdr);

	// calculate size needed for .dynstr/.dynsym/.gnu.version

	*add_dynstr_size = 0;
	*new_symbols = 0;

	for (int i = 0; i < symbol_count; i++) {
		Elf64_Sym *victim_sym = get_symbol(bin, symbol_names[i], true);

		if (!victim_sym) {
			// .dynstr/.dynsym needs to be moved into new region
			*add_dynstr_size += strlen(symbol_names[i]) + 1;
			(*new_symbols)++;
		}
	}

	uint64_t add_size = 0;

	if (*add_dynstr_size > 0) {
		// .dynstr
		add_size += bin->dynstr_shdr->sh_size + *add_dynstr_size;
		// .dynsym
		add_size += bin->dynsym_shdr->sh_size + *new_symbols * sizeof(Elf64_Sym);
		// .gnu.version
		if (bin->gnu_ver_shdr)
			add_size += bin->gnu_ver_shdr->sh_size + *new_symbols * sizeof(Elf64_Versym);
	}

	// add size for number of needed relocations
	add_size += rela_shdr->sh_size + reloc_count * sizeof(Elf64_Rela);

	return add_size;
}

// expand a segment and move .dynstr/.dynsym (if required dynamic symbols are not available
// in the binary), .rela.dyn (or .rela.plt) and .gnu.version to expanded location
// specify segment_id to expand specific segment
void expand_and_move(elf_bin *bin, uint64_t add_size, int segment_id, uint64_t add_dynstr_size, uint64_t new_symbols)
{
	Elf64_Phdr *expanded_segment = 0;
	uint64_t region_offset = 0;

	// find segment to expand
	for (int i = 0; i < bin->ehdr->e_phnum; i++) {
		if (bin->phdr[i].p_type == PT_LOAD) {
			if (segment_id < 1 && (region_offset = expand_segment(bin, i, add_size))) {
				expanded_segment = &bin->phdr[i];
				break;
			}
			if (segment_id == 0) {
				fprintf(stderr, "error: segment not expandable\n");
				exit(1);
			}

			segment_id--;
		}
	}

	if (!expanded_segment) {
		// actually it should never happen, but just in case
		fprintf(stderr, "error: failed to find an expandable segment\n");
		exit(1);
	}

	Elf64_Shdr *rela_shdr = (bin->rela_dyn_shdr ? bin->rela_dyn_shdr : bin->rela_plt_shdr);

	// move sections to expanded region

	if (add_dynstr_size > 0) {
		// move .dynstr
		move_section(bin, bin->dynstr_shdr, expanded_segment->p_offset + region_offset,
											expanded_segment->p_vaddr + region_offset);
		region_offset += bin->dynstr_shdr->sh_size + add_dynstr_size;

		// move .dynsym
		move_section(bin, bin->dynsym_shdr, expanded_segment->p_offset + region_offset,
											expanded_segment->p_vaddr + region_offset);
		region_offset += bin->dynsym_shdr->sh_size + new_symbols * sizeof(Elf64_Sym);

		if (bin->gnu_ver_shdr) {
			// move .gnu.version
			// it only needs to move the section and resize, and no editing needed
			// because the later part is initialized with zeroes, which is what we want
			move_section(bin, bin->gnu_ver_shdr, expanded_segment->p_offset + region_offset,
												expanded_segment->p_vaddr + region_offset);
			bin->gnu_ver_shdr->sh_size += new_symbols * sizeof(Elf64_Versym);
			region_offset += bin->gnu_ver_shdr->sh_size;
		}
	}

	// move .rela.dyn (or .rela.plt)
	move_section(bin, rela_shdr, expanded_segment->p_offset + region_offset,
								expanded_segment->p_vaddr + region_offset);
}

// inject symbol name in .dynstr and symbol in .dynsym
void inject_dynstr_dynsym(elf_bin *bin, char **symbol_names, int symbol_count)
{
	for (int i = 0; i < symbol_count; i++) {
		Elf64_Sym *victim_sym = get_symbol(bin, symbol_names[i], true);

		if (!victim_sym) {
			// inject string .dynstr
			printf("victim symbol not found: injecting %s...\n", symbol_names[i]);

			memcpy(bin->dynstr + bin->dynstr_shdr->sh_size, symbol_names[i], strlen(symbol_names[i]) + 1);

			// inject symbol in .dynsym
			Elf64_Sym *sym = (Elf64_Sym *)((char *)bin->dynsym + bin->dynsym_shdr->sh_size);

			sym->st_name = bin->dynstr_shdr->sh_size;
			sym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_OBJECT);
			sym->st_other = STV_DEFAULT;
			sym->st_shndx = 0;
			sym->st_value = 0;
			sym->st_size = 0;

			// update headers
			bin->dynstr_shdr->sh_size += strlen(symbol_names[i]) + 1;
			bin->dynsym_shdr->sh_size += sizeof(Elf64_Sym);
		}
	}
}

// disable .gnu.version/.gnu.version_r
void disable_gnu_version(elf_bin *bin)
{
	delete_tag(bin, DT_VERSYM);
	delete_tag(bin, DT_VERNEED);
	delete_tag(bin, DT_VERNEEDNUM);
}

// make segments writable where modifications are done
void set_segments_writable(elf_bin *bin, memory **mods, int mod_count)
{
	bool textrel = false;

	// set DF_TEXTREL in DT_FLAGS
	// this makes text section temporarily writable while relocating
	Elf64_Dyn *flags = get_tag(bin, DT_FLAGS);

	for (int i = 0; i < mod_count; i++) {
		uint64_t addr = mods[i]->addr;

		for (int j = 0; j < mods[i]->size; j++) {
			Elf64_Phdr *segment = get_segment(bin, addr + j);

			if (!segment) {
				fprintf(stderr, "warning: relocation out of bound at %lx, cannot set writable permission\n", addr + j);
				continue;
			}
			// nothing to do if it's already writable
			if (segment->p_flags & PF_W)
				continue;
			// in case of executable it will be fixed with another approach, as long as DT_FLAGS is available
			if (flags && segment->p_flags & PF_X) {
				textrel = true;
				continue;
			}

			printf("setting writable permission to segment with address %lx - %lx\n", segment->p_vaddr, segment->p_vaddr + segment->p_memsz);
			segment->p_flags |= PF_W;
		}
	}

	// set DF_TEXTREL in DT_FLAGS
	// this makes text section temporarily writable while relocating
	if (textrel) {
		Elf64_Dyn *flags = get_tag(bin, DT_FLAGS);
		if (!flags) {
			fprintf(stderr, "warning: could not find DT_FLAGS tag, probably won't work as intended\n");
		}

		printf("setting DF_TEXTREL in DT_FLAGS\n");

		flags->d_un.d_val |= DF_TEXTREL;
	}
}

// returns the number of bytes that can be abused/controlled to get arbitrary value
// note that in some cases it does not match with the actual size of bytes that will be written
int reloc_write_size(int type)
{
	switch (type) {
		case R_X86_64_SIZE32:
			return 4;
		case R_X86_64_SIZE64:
			return 8;
		case R_X86_64_64:
			return 1;
		case R_X86_64_RELATIVE:
			return 1;
	}

	return 0;
}

// finds next rela to overwrite
// searches for magic number in the addend
Elf64_Rela *find_next_rela(Elf64_Rela *start, Elf64_Rela *end)
{
	printf("start end distance: %ld\n", ((uint64_t)end - (uint64_t)start) / sizeof(Elf64_Rela));

	for (; start != end; start++) {
		if (start->r_addend == 0x0bf5ca7e)
			return start;
	}

	return 0;
}

// injects a relocation in relocation table
void inject_rela(elf_bin *bin, memory **mods, int mod_count, bool replace)
{
	// good luck reading this mountain

	Elf64_Shdr *rela_shdr = (bin->rela_dyn_shdr ? bin->rela_dyn_shdr : bin->rela_plt_shdr);
	Elf64_Rela *rela_start = (Elf64_Rela *)(bin->bytes + rela_shdr->sh_offset);
	Elf64_Rela *rela_end = rela_start + rela_shdr->sh_size / sizeof(Elf64_Rela);
	Elf64_Rela *rela = rela_end;

	if (replace)
		rela = find_next_rela(rela_start, rela_end);

	for (int i = 0; i < mod_count; i++) {
		// memory address in the binary where the obfuscation will be done
		uint64_t addr = mods[i]->addr;

		// get the symbol id to use for the relocation
		Elf64_Sym *victim_sym = get_symbol(bin, mods[i]->reloc.name, true);
		uint64_t sym_idx = ((uint64_t)victim_sym - (uint64_t)bin->dynsym) / sizeof(Elf64_Sym);

		// build the addend value for one relocation
		for (int j = 0; j < mods[i]->size; j += mods[i]->reloc.size) {
			if (!rela) {
				fprintf(stderr, "error: not enough replaceable relocations\n");
				exit(1);
			}

			uint64_t value = 0;

			for (int b = 0; b < reloc_write_size(mods[i]->reloc.type); b++) {
				uint64_t byte = 0;
				bool recover_bytes = false;

				if (j + b >= mods[i]->size &&
						j + reloc_write_size(mods[i]->reloc.type) > mods[i]->size) {
					// last relocation, which will corrupt some original bytes
					if (mods[i]->reloc.dirty)
						break;
					recover_bytes = true;
				} else if (!(b < mods[i]->reloc.size && j + b < mods[i]->size)) {
					break;
				} else {
					byte = mods[i]->values[j + b];
				}
				if (!mods[i]->reloc.overwrite || recover_bytes) {
					uint64_t byte_offset = addr_to_offset(bin, addr + j + b);

					if (byte_offset == -1) {
						fprintf(stderr, "warning: relocation out of bound at %lx\n", addr + j);
					} else {
						byte = bin->bytes[byte_offset];
						if (!recover_bytes)
							bin->bytes[byte_offset] = mods[i]->values[j + b];
					}
				}
				value |= (uint64_t)byte << (8 * b);
			}

			if (mods[i]->reloc.type != R_X86_64_RELATIVE) {
				// subtract the expected addend value of the symbol
				// REL8 (R_X86_64_RELATIVE) will always have 00 and don't need to be adjusted
				value -= mods[i]->reloc.addend;
			}

			rela->r_offset = addr + j;
			rela->r_info = ELF64_R_INFO(sym_idx, mods[i]->reloc.type);
			rela->r_addend = value;

			if (!replace) {
				// go to next uninitialized rela
				rela_shdr->sh_size += sizeof(Elf64_Sym);
				rela++;
			} else {
				// find next rela with magic number
				rela = find_next_rela(rela + 1, rela_end);
			}
		}
	}
}

// compare two relocation based on offset, used for qsort
int cmp_rela(const void *a, const void *b)
{
	return ((Elf64_Rela *)a)->r_offset - ((Elf64_Rela *)b)->r_offset;
}

// determine whether a binary is relobfuscated or not
void is_relobfuscated(const char *input)
{
	// load the binary to obfuscate
	elf_bin *bin = load_elf(input);

	// check that it is a elf binary
	if (!bin)
		exit(1);

	if (!bin->rela_dyn_shdr && !bin->rela_plt_shdr) {
		fprintf(stderr, "error: section .rela.dyn/.rela.plt not found\n");
		exit(1);
	}

	uint64_t rela_size = 0;
	Elf64_Rela *rela = 0;

	if (bin->rela_dyn_shdr) {
		uint64_t offset = rela_size;
		rela_size += bin->rela_dyn_shdr->sh_size;
		rela = realloc(rela, rela_size);

		memcpy((char *)rela + offset, bin->rela_dyn, bin->rela_dyn_shdr->sh_size);
	}
	if (bin->rela_plt_shdr) {
		uint64_t offset = rela_size;
		rela_size += bin->rela_plt_shdr->sh_size;
		rela = realloc(rela, rela_size);

		memcpy((char *)rela + offset, bin->rela_plt, bin->rela_plt_shdr->sh_size);
	}

	bool unaligned = false;
	bool intersect = false;
	bool type_size = false;

	// TODO: allocate array and put both sections in same shit

	uint64_t rela_count = rela_size / sizeof(Elf64_Rela);

	// sort rela based on offset to make it easy to check intersects
	qsort(rela, rela_count, sizeof(Elf64_Rela), cmp_rela);

	for (int i = 0; i < rela_count; i++) {
		int type = ELF64_R_TYPE(rela[i].r_info);
		int size = reloc_size(type);

		printf("addr: %lx (size: %d, type: %d)\n", rela[i].r_offset, size, type);

		// check if relocation isn't 8-byte aligned
		if (size > 0 && rela[i].r_offset & 0x7) {
			unaligned = true;
			printf("unaligned addr: %lx (size: %d)\n", rela[i].r_offset, size);
		}

		// check if relocation intersects with next
		if (i + 1 < rela_count &&
				rela[i].r_offset + size > rela[i+1].r_offset) {
			intersect = true;
			printf("intersect addr: %lx (size: %d)\n", rela[i].r_offset, size);
		}

		// nobody uses R_X86_64_SIZE32/64
		if (type == R_X86_64_SIZE32 || type == R_X86_64_SIZE64)
			type_size = true;
	}

	if (unaligned)
		printf("found unaligned relocation(s), potentially relobfuscated\n");

	if (intersect)
		printf("found intersecting relocations, 100%% relobfuscated\n");

	if (type_size)
		printf("found R_X86_64_SIZE relocation(s), potentially relobfuscated\n");

	// clean the toilet

	free(rela);
	free_elf(bin);
}

// write a relocation c file
void generate_c_file(const char *output, const char *script, bool sort)
{
	memory **mods = 0;
	int mod_count = 0;

	// load the obfuscation script
	if (!read_reloc_script(script, NULL, sort, &mods, &mod_count))
		exit(1);

	// print obfuscations to be done
	print_memory_modifications(mods, mod_count);

	// create output c file
	FILE *file = fopen(output, "w");
	if (!file) {
		fprintf(stderr, "error: failed to create file: %s\n", output);
		exit(1);
	}

	// write scape goat array
	fprintf(file, "char *relobfuscate[] = {");

	for (int i = 0; i < mod_count; i++) {
		int symbols = required_relocs(mods + i, 1);

		for (int j = 0; j < symbols; j++)
			fprintf(file, "(char*)&%s+0x0bf5ca7e,", mods[i]->reloc.name);
	}

	fprintf(file, "};\n");

	// clean up
	fclose(file);

	free_memories(mods, mod_count);
}

// relobfuscate a binary
void relobfuscate(const char *input, const char *output, const char *script, int segment_id, bool replace, bool sort, bool disable_version)
{
	// load the binary to obfuscate
	elf_bin *bin = load_elf(input);

	// check that it is a elf binary
	if (!bin)
		exit(1);
	// check that it meets the requirements
	if (!check_elf_requirements(bin))
		exit(1);

	memory **mods = 0;
	int mod_count = 0;

	// load the obfuscation script
	if (!read_reloc_script(script, bin, sort, &mods, &mod_count))
		exit(1);

	// print obfuscations to be done
	print_memory_modifications(mods, mod_count);

	// get dynamic symbol names
	int symbol_count = 0;
	char **symbol_names = memories_symbol_names(mods, mod_count, &symbol_count);

	// expand a segment and inject stuff
	if (!replace) {
		// calculate size to expand a segment with
		uint64_t add_dynstr_size = 0;
		uint64_t new_symbols = 0;
		uint64_t add_size = calculate_add_size(bin, required_relocs(mods, mod_count), symbol_names, symbol_count, &add_dynstr_size, &new_symbols);

		// expand a segment and move relevant sections there
		expand_and_move(bin, add_size, segment_id, add_dynstr_size, new_symbols);

		// inject stuff in the moved sections

		// inject in .dynstr/.dynsym
		if (add_dynstr_size != 0) {
			inject_dynstr_dynsym(bin, symbol_names, symbol_count);
		}
	}

	// inject in .rela.dyn (or .rela.plt)
	inject_rela(bin, mods, mod_count, replace);

	// update dynamic segment
	update_dynamic(bin);

	// make sure all addresses have writable segment
	set_segments_writable(bin, mods, mod_count);

	// disable gnu version shits
	if (disable_version)
		disable_gnu_version(bin);

	// save the binary
	write_elf(bin, output);

	// free shits and shits
	free_symbol_names(symbol_names, symbol_count);
	free_memories(mods, mod_count);
	free_elf(bin);
}

// maybe main
int main(int argc, char **argv)
{
	const char *input = 0, *output = 0, *script = 0, *reloc_c = 0, *detect = 0;
	bool replace = false, sort = true, disable_version = false;
	int segment_id = -1;

	// parse flags
	int opt = 0;
	while ((opt = getopt(argc, argv, ":i:o:s:rnvp:c:d:h")) != -1) {
		switch (opt) {
			case 'i':
				input = optarg;
				break;
			case 'o':
				output = optarg;
				break;
			case 's':
				script = optarg;
				break;
			case 'r':
				replace = true;
				break;
			case 'n':
				sort = false;
				break;
			case 'v':
				disable_version = true;
				break;
			case 'p':
				segment_id = atoi(optarg);
				break;
			case 'c':
				reloc_c = optarg;
				break;
			case 'd':
				detect = optarg;
				break;
			case 'h':
				help(argv[0]);
				exit(0);
				break;
			case ':':
				fprintf(stderr, "error: flag -%c requires a value\n", optopt);
				exit(1);
				break;
			case '?':
				fprintf(stderr, "error: unknown flag -%c\n", optopt);
				exit(1);
		}
	}

	if (reloc_c && script) {
		// generate a relocation c file
		generate_c_file(reloc_c, script, sort);
	} else if (detect) {
		// check if a binary is relobfuscated
		is_relobfuscated(detect);
	} else if (input && output && script) {
		// relobfuscate a binary
		relobfuscate(input, output, script, segment_id, replace, sort, disable_version);
	} else {
		help(argv[0]);
		exit(0);
	}

	return 0;
}
