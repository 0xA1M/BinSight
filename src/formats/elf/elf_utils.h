#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  // Raw parsed headers
  void *ehdr;  // Elf32_Ehdr* or Elf64_Ehdr*
  void *phdrs; // Program headers array
  int phnum;

  void *shdrs; // Section headers array
  int shnum;

  char *shstrtab; // Section header string table
  char *strtab;   // .strtab (for symbols)
  void *symtab;   // Elf32_Sym* or Elf64_Sym*
  int sym_count;

  void *rela; // Relocation entries (if any)
  int rela_count;

  // Optional flags or extra parsed info
  bool has_interp;
} ELFInfo;

ELFInfo *init_elf(void);
void free_elf(ELFInfo *);

uint16_t read_elf_half(const unsigned char *, size_t, bool);
uint32_t read_elf_word(const unsigned char *, size_t, bool);
uint64_t read_elf_xword(const unsigned char *, size_t, bool);

void print_elf_header(void *);

#endif // ELF_UTILS_H
