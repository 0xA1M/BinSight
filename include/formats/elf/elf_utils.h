#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>

#include "core/mem.h"

typedef struct ELFPhdrs {
  Elf64_Phdr *headers;
  uint16_t count;
  uintptr_t offset;
  uint64_t entry_size;
} ELFPhdrs;

typedef struct ELFShdrs {
  Elf64_Shdr *headers;
  uint16_t count;
  uintptr_t offset;
  uint64_t entry_size;

  String strtab;
  uint64_t strtab_off;
  uint16_t strtab_ndx;
} ELFShdrs;

typedef struct ELFSymTab {
  Elf64_Sym *symbols;
  uint64_t count;
  uintptr_t offset;
  uint64_t entry_size;

  String strtab;
} ELFSymTab;

typedef struct ELFDynTab {
  Elf64_Dyn *entries;
  uint64_t count;
  uintptr_t offset;
  uint64_t entry_size;
} ELFDynTab;

typedef struct ELFInfo {
  Elf64_Ehdr *ehdr;

  ELFPhdrs phdrs;
  ELFShdrs shdrs;
  ELFSymTab symtab;
  ELFSymTab dynsym;
  ELFDynTab dynamic;

  String interp;

  Elf64_Rela *rela;
  int rela_count;
} ELFInfo;

ELFInfo *init_elf(Arena *arena);

const Elf64_Shdr *elf_get_section_by_type(const ELFShdrs *shdrs, uint32_t type);
const Elf64_Phdr *elf_get_segment_by_type(const ELFPhdrs *phdrs, uint32_t type);

#endif // ELF_UTILS_H
