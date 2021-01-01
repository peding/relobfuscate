#ifndef __ELFER_H__
#define __ELFER_H__

#include <elf.h>
#include <stdbool.h>

typedef struct _elf_bin {
	uint8_t *bytes;
	uint64_t size;

	// elf headers

	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;

	// section headers

	Elf64_Shdr *dyn_shdr;
	Elf64_Shdr *strtab_shdr, *symtab_shdr;
	Elf64_Shdr *dynstr_shdr, *dynsym_shdr;
	Elf64_Shdr *rela_dyn_shdr, *rela_plt_shdr;
	Elf64_Shdr *gnu_ver_shdr;

	// sections

	Elf64_Dyn *dyn;

	char *shstrtab, *strtab, *dynstr;
	Elf64_Sym *symtab, *dynsym;

	Elf64_Rela *rela_dyn, *rela_plt;

} elf_bin;

Elf64_Shdr *get_section_header(const elf_bin *bin, const char *name);
Elf64_Sym *get_symbol(const elf_bin *bin, const char *name, bool dynsym);
Elf64_Phdr *get_program_header(const elf_bin *bin, uint32_t type);
Elf64_Phdr *get_segment(const elf_bin *bin, uint64_t addr);
Elf64_Dyn *get_tag(const elf_bin *bin, int64_t tag);

uint64_t addr_to_offset(const elf_bin *bin, uint64_t addr);
int reloc_size(int type);

void move_section(elf_bin *bin, Elf64_Shdr *section_header, uint64_t new_offset, uint64_t new_addr);
uint64_t expand_segment(elf_bin *bin, int segment_id, uint64_t add_size);
void delete_tag(elf_bin *bin, int64_t tag);
void update_dynamic(elf_bin *bin);

void update_elf_pointers(elf_bin *bin);

elf_bin *load_elf(const char *path);
bool write_elf(const elf_bin *bin, const char *path);
void free_elf(elf_bin *bin);

#endif

