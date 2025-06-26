#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  // Raw parsed headers
  void *ehdr; // Elf32_Ehdr* or Elf64_Ehdr*

  void *phdrs; // Program headers array
  void *shdrs; // Section headers array

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

uint8_t read_byte(const unsigned char *buf, size_t offset);
uint16_t read_word(const unsigned char *buf, size_t offset,
                   bool is_little_endian);
uint32_t read_dword(const unsigned char *buf, size_t offset,
                    bool is_little_endian);
uint64_t read_qword(const unsigned char *buf, size_t offset,
                    bool is_little_endian);

void print_elf_ehdr(void *ehdr);
void print_elf_phdrs(const void *phdrs, int bitness, const uint16_t phnum);
void print_elf_shdrs(const void *shdrs, int bitness, const uint16_t shnum,
                     const char *shstrtab);

#endif // ELF_UTILS_H
