#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/mem.h"

typedef struct Needed_Lib {
  const char *name;
  struct Needed_Lib *next;
} Needed_Lib;

typedef struct {
  // ELF Header
  Elf64_Ehdr *ehdr;

  // Program Headers Table
  Elf64_Phdr *phdrs;
  uint64_t phnum;
  uint64_t phoff;
  uint16_t phentsize;

  // Section Headers Table
  Elf64_Shdr *shdrs;
  uint64_t shnum;
  uint64_t shoff;
  uint16_t shentsize;

  const char *shstrtab;
  uint16_t shstrndx;
  uint64_t shstrtab_off;
  uint64_t shstrtab_size;

  Elf64_Sym *symtab;
  uint64_t sym_count;
  const char *strtab;
  uint64_t strtab_size;

  Elf64_Sym *dynsym;
  uint64_t dyn_count;
  const char *dynstr;
  uint64_t dynstr_size;

  const char *interpreter;
  uint64_t interp_str_size;

  Elf64_Dyn *dynamic;
  uint64_t dynamic_off;
  uint64_t dynamic_entsz;
  uint64_t dynamic_count;
  Needed_Lib *lib;
  const char *soname;
  const char *rpath;
  const char *runpath;
  uint64_t pltgot;
  uint64_t jmprel;
  uint64_t rela_off;
  uint64_t rela_size;
  uint64_t rela_entsz;
  uint64_t rel_off;
  uint64_t rel_size;
  uint64_t rel_entsz;
  uint64_t hash_off;
  uint64_t gnu_hash_off;

  Elf64_Rela *rela;
  int rela_count;
} ELFInfo;

ELFInfo *init_elf(Arena *arena);
int find_shdr(Arena *arena, const Elf64_Shdr *shdrs, const uint64_t shnum,
              uint32_t target_type);
int find_phdr(Arena *arena, const Elf64_Phdr *phdrs, const uint64_t phnum,
              uint32_t target_type);

#endif // ELF_UTILS_H
