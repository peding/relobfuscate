#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "elfer.h"

// returns section header from name
Elf64_Shdr *get_section_header(const elf_bin *bin, const char *name)
{
	if (!bin)
		return 0;

	// compare names to find the symbol
	for (int i = 0; i < bin->ehdr->e_shnum; i++) {
		const char *section_name = bin->shstrtab + bin->shdr[i].sh_name;

		if (!strcmp(section_name, name))
			return &bin->shdr[i];
	}

	return 0;
}

// returns symbol from name
// if use_dynsym is false it uses .symtab and .strtab
// if use_dynsym is true it uses .dynsym and .dynstr
Elf64_Sym *get_symbol(const elf_bin *bin, const char *name, bool use_dynsym)
{
	if (!bin)
		return 0;

	// choose what symbol/string tables to use
	Elf64_Sym *syms = use_dynsym ? bin->dynsym : bin->symtab;
	uint64_t syms_count = (use_dynsym ? bin->dynsym_shdr->sh_size : bin->symtab_shdr->sh_size) / sizeof(Elf64_Sym);
	char *strtab = use_dynsym ? bin->dynstr : bin->strtab;

	// make sure the tables are available
	if (!syms || !strtab)
		return 0;

	// compare names to find the symbol
	for (int i = 0; i < syms_count; i++) {
		const char *sym_name = strtab + syms[i].st_name;

		if (!strcmp(sym_name, name))
			return &syms[i];
	}

	return 0;
}

// return program header from type
// not made for finding multiple program headers with same type
Elf64_Phdr *get_program_header(const elf_bin *bin, uint32_t type)
{
	// go through program headers
	for (int i = 0; i < bin->ehdr->e_phnum; i++) {
		if (bin->phdr[i].p_type == type)
			return &bin->phdr[i];
	}

	return 0;
}

// returns segment from memory address
Elf64_Phdr *get_segment(const elf_bin *bin, uint64_t addr)
{
	// go through program headers
	for (int i = 0; i < bin->ehdr->e_phnum; i++) {
		// go to next if it's not segment
		if (bin->phdr[i].p_type != PT_LOAD)
			continue;

		// return if the address is in the segment memory range
		if (bin->phdr[i].p_vaddr <= addr && addr < bin->phdr[i].p_vaddr + bin->phdr[i].p_memsz) {
			return &bin->phdr[i];
		}
	}

	return 0;
}

// returns a dynamic tag
Elf64_Dyn *get_tag(const elf_bin *bin, int64_t tag)
{
	// loop through tags
	for (int i = 0; i < bin->dyn_shdr->sh_size / sizeof(Elf64_Dyn); i++) {
		if (bin->dyn[i].d_tag == tag)
			return &bin->dyn[i];
	}

	return 0;
}

// convert memory address to file offset
// returns -1 if the address is outside binary
uint64_t addr_to_offset(const elf_bin *bin, uint64_t addr)
{
	Elf64_Phdr *segment = get_segment(bin, addr);
	if (segment)
			return segment->p_offset + (addr - segment->p_vaddr);
	return -1;
}

// returns the number of bytes that the relocation will write
int reloc_size(int type)
{

	switch (type) {
		case R_X86_64_8:
		case R_X86_64_PC8:
			return 1;
		case R_X86_64_16:
		case R_X86_64_PC16:
			return 2;
		case R_X86_64_SIZE32:
		case R_X86_64_PC32:
		case R_X86_64_GOT32:
		case R_X86_64_PLT32:
		case R_X86_64_GOTPCREL:
		case R_X86_64_32:
		case R_X86_64_32S:
		case R_X86_64_TLSGD:
		case R_X86_64_TLSLD:
		case R_X86_64_DTPOFF32:
		case R_X86_64_GOTTPOFF:
		case R_X86_64_TPOFF32:
			return 4;
		case R_X86_64_SIZE64:
		case R_X86_64_64:
		case R_X86_64_GLOB_DAT:
		case R_X86_64_JUMP_SLOT:
		case R_X86_64_RELATIVE:
		case R_X86_64_DTPMOD64:
		case R_X86_64_DTPOFF64:
		case R_X86_64_TPOFF64:
			return 8;
	}

	return 0;
}

// move a section to new offset
// the old place will be filled with zeroes
void move_section(elf_bin *bin, Elf64_Shdr *section_header, uint64_t new_offset, uint64_t new_addr)
{
	const char *section_name = bin->shstrtab + section_header->sh_name;

	printf("moving %s from %lx to %lx\n", section_name, section_header->sh_offset, new_offset);

	// copy to new offset
	memmove(bin->bytes + new_offset, bin->bytes + section_header->sh_offset, section_header->sh_size);
	// clean the old place
	memset(bin->bytes + section_header->sh_offset, 0, section_header->sh_size);
	// update section header
	section_header->sh_offset = new_offset;
	section_header->sh_addr = new_addr;

	// update headers and pointers
	update_dynamic(bin);
	update_elf_pointers(bin);
}

// expand a segment with at least add_size bytes
// it may expand with more bytes than add_size to keep the alignments in file/memory
uint64_t expand_segment(elf_bin *bin, int segment_id, uint64_t add_size)
{
	// why would you write a program that gives wrong id in the first place?
	if (segment_id >= bin->ehdr->e_phnum || bin->phdr[segment_id].p_type != PT_LOAD)
		return 0;

	// bss_start == bss_end if there is no bss region in the segment
	uint64_t bss_start = bin->phdr[segment_id].p_offset + bin->phdr[segment_id].p_filesz;
	uint64_t bss_end = bin->phdr[segment_id].p_offset + bin->phdr[segment_id].p_memsz;
	uint64_t bss_size = bss_end - bss_start;

	bool last_segment = (segment_id + 1 == bin->ehdr->e_phnum) || (bin->phdr[segment_id+1].p_type != PT_LOAD);

	add_size += bss_size; // .bss section
	// if it's not last segment, then the additional size must be multiple of 4096
	// because segments offset and address requires to be aligned in same way
	if (!last_segment)
		add_size = (add_size + 0xfff) & ~0xfff;

	// make sure the segment memory region do not intersect with the next segment memory region
	// (assumption: segments must be continuous in program headers?)
	if (!last_segment &&
			bin->phdr[segment_id].p_vaddr + bin->phdr[segment_id].p_filesz + add_size > bin->phdr[segment_id+1].p_vaddr) {
		return 0;
	}

	// fix program header for the segment to be expanded
	bin->phdr[segment_id].p_filesz += add_size;
	bin->phdr[segment_id].p_memsz = bin->phdr[segment_id].p_filesz;

	// fix other program headers

	for (int i = 0; i < bin->ehdr->e_phnum; i++) {
		printf("program header %d: %8lx %8lx\n", i, bin->phdr[i].p_offset, bin->phdr[i].p_memsz);

		if (i == segment_id)
			continue;
		if (bss_start >= bin->phdr[i].p_offset)
			continue;

		bin->phdr[i].p_offset += add_size;

		printf("moved program id %d offset to %lx\n", i, bin->phdr[i].p_offset);
	}

	// fix elf header

	if (bin->ehdr->e_shoff >= bss_start)
		bin->ehdr->e_shoff += add_size;
	if (bin->ehdr->e_shstrndx >= bss_start)
		bin->ehdr->e_shstrndx += add_size;

	// fix section headers

	for (int i = 0; i < bin->ehdr->e_shnum; i++) {
		if (bin->shdr[i].sh_offset >= bss_start)
			bin->shdr[i].sh_offset += add_size;
	}

	// fix dynamic section

	update_dynamic(bin);

	// resize the bin

	uint8_t *new_bytes = malloc(bin->size + add_size);

	memcpy(new_bytes, bin->bytes, bss_start);
	memset(new_bytes + bss_start, 0, add_size);
	memcpy(new_bytes + bss_start + add_size, bin->bytes + bss_start, bin->size - bss_start);

	free(bin->bytes);
	bin->bytes = new_bytes;
	bin->size += add_size;

	// update elf pointers since they are no longer valid
	update_elf_pointers(bin);

	printf("expanded segment with %lx bytes\n", add_size);

	// return the internal offset in the segment that expanded region starts at
	return bss_start + bss_size - bin->phdr[segment_id].p_offset;
}

// delete a tag from dynamic section
void delete_tag(elf_bin *bin, int64_t tag)
{
	int count = bin->dyn_shdr->sh_size / sizeof(Elf64_Dyn);

	for (int i = 0; i < count; i++) {
		if (bin->dyn[i].d_tag == tag) {
			// replace it with last tag
			Elf64_Dyn *last = &bin->dyn[count-1];
			if (i < count - 1)
				memmove(&bin->dyn[i], &bin->dyn[i+1], (count - i - 1) * sizeof(Elf64_Dyn));

			memset(last, 0, sizeof(Elf64_Dyn));

			// fix headers
			bin->dyn_shdr->sh_size -= sizeof(Elf64_Dyn);

			Elf64_Phdr *dyn_phdr = get_program_header(bin, PT_DYNAMIC);
			dyn_phdr->p_filesz -= sizeof(Elf64_Dyn);
			dyn_phdr->p_memsz -= sizeof(Elf64_Dyn);

			break;
		}
	}
}

// update dynamic tags based on section header informations
void update_dynamic(elf_bin *bin)
{
	for (int i = 0; i < bin->dyn_shdr->sh_size / sizeof(Elf64_Dyn); i++) {
		switch (bin->dyn[i].d_tag) {
			case DT_STRTAB: // .dynstr address
				bin->dyn[i].d_un.d_val = bin->dynstr_shdr->sh_addr;
				break;
			case DT_STRSZ: // .dynstr size
				bin->dyn[i].d_un.d_val = bin->dynstr_shdr->sh_size;
				break;
			case DT_SYMTAB: // .symtab address
				bin->dyn[i].d_un.d_val = bin->dynsym_shdr->sh_addr;
				break;
			case DT_RELA: // .rela.dyn address
				bin->dyn[i].d_un.d_val = bin->rela_dyn_shdr->sh_addr;
				break;
			case DT_RELASZ: // .rela.dyn size
				bin->dyn[i].d_un.d_val = bin->rela_dyn_shdr->sh_size;
				break;
			case DT_JMPREL: // .rela.plt address
				bin->dyn[i].d_un.d_val = bin->rela_plt_shdr->sh_addr;
				break;
			case DT_PLTRELSZ: // .rela.plt size
				bin->dyn[i].d_un.d_val = bin->rela_plt_shdr->sh_size;
				break;
			case DT_VERSYM: // .gnu.version address
				bin->dyn[i].d_un.d_val = bin->gnu_ver_shdr->sh_addr;
				break;
		}
	}
}

// update elf pointers in elf_bin structure
void update_elf_pointers(elf_bin *bin)
{
	bin->ehdr = (Elf64_Ehdr *)bin->bytes;

	bin->phdr = (Elf64_Phdr *)(bin->bytes + bin->ehdr->e_phoff);
	bin->shdr = (Elf64_Shdr *)(bin->bytes + bin->ehdr->e_shoff);

	// process section headers

	bin->shstrtab = (char *)(bin->bytes + bin->shdr[bin->ehdr->e_shstrndx].sh_offset);

	bin->dyn_shdr = get_section_header(bin, ".dynamic");

	bin->strtab_shdr = get_section_header(bin, ".strtab");
	bin->symtab_shdr = get_section_header(bin, ".symtab");

	bin->dynstr_shdr = get_section_header(bin, ".dynstr");
	bin->dynsym_shdr = get_section_header(bin, ".dynsym");

	bin->rela_dyn_shdr = get_section_header(bin, ".rela.dyn");
	bin->rela_plt_shdr = get_section_header(bin, ".rela.plt");

	bin->gnu_ver_shdr = get_section_header(bin, ".gnu.version");

	// process sections

	if (bin->dyn_shdr)
		bin->dyn = (Elf64_Dyn *)(bin->bytes + bin->dyn_shdr->sh_offset);

	if (bin->strtab_shdr)
		bin->strtab = (char *)(bin->bytes + bin->strtab_shdr->sh_offset);
	if (bin->symtab_shdr)
		bin->symtab = (Elf64_Sym *)(bin->bytes + bin->symtab_shdr->sh_offset);

	if (bin->dynstr_shdr)
		bin->dynstr = (char *)(bin->bytes + bin->dynstr_shdr->sh_offset);
	if (bin->dynsym_shdr)
		bin->dynsym = (Elf64_Sym *)(bin->bytes + bin->dynsym_shdr->sh_offset);

	if (bin->rela_dyn_shdr)
		bin->rela_dyn = (Elf64_Rela *)(bin->bytes + bin->rela_dyn_shdr->sh_offset);
	if (bin->rela_plt_shdr)
		bin->rela_plt = (Elf64_Rela *)(bin->bytes + bin->rela_plt_shdr->sh_offset);
}

// load a binary from pathh
elf_bin *load_elf(const char *path)
{
	// open binary

	FILE *file = fopen(path, "rb");
	if (!file) {
		fprintf(stderr, "error: failed to open file: %s\n", path);
		return 0;
	}

	elf_bin *bin = calloc(1, sizeof(elf_bin));

	// get file size
	fseek(file, 0, SEEK_END);
	bin->size = ftell(file);
	fseek(file, 0, SEEK_SET);

	// read into memory
	bin->bytes = malloc(bin->size);
	fread(bin->bytes, 1, bin->size, file);

	fclose(file);

	bin->ehdr = (Elf64_Ehdr *)bin->bytes;

	// check elf magic

	if (memcmp(bin->ehdr->e_ident, ELFMAG, SELFMAG)) {
		fprintf(stderr, "error: incorrect elf magic\n");
		free_elf(bin);
		return 0;
	}

	// check that it's 64-bit

	if (bin->ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "error: not a 64-bit binary\n");
		free_elf(bin);
		return 0;
	}

	// check that it's for x86-64

	if (bin->ehdr->e_machine != EM_X86_64) {
		fprintf(stderr, "error: not a x86-64 binary\n");
		return 0;
	}

	// process pointers

	update_elf_pointers(bin);

	return bin;
}

// write elf binary into file
bool write_elf(const elf_bin *bin, const char *path)
{
	FILE *file = fopen(path, "wb");
	if (!file) {
		fprintf(stderr, "error: failed to create file: %s\n", path);
		return false;
	}

	fwrite(bin->bytes, 1, bin->size, file);

	fclose(file);

	chmod(path, 0755);

	return true;
}

// free elf
void free_elf(elf_bin *bin)
{
	free(bin->bytes);
	free(bin);
}

