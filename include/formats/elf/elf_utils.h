#ifndef ELF_UTILS_H
#define ELF_UTILS_H

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/mem.h"

typedef struct {
  Elf64_Ehdr *ehdr;

  Elf64_Phdr *phdrs;
  uint64_t phnum;
  uint64_t phoff;
  uint16_t phentsize;

  Elf64_Shdr *shdrs;
  uint64_t shnum;
  uint64_t shoff;
  uint16_t shentsize;

  char *shstrtab;
  uint16_t shstrndx;
  uint64_t shstrtab_off;
  uint64_t shstrtab_size;

  Elf64_Sym *symtab;
  uint64_t sym_count;
  char *strtab;

  Elf64_Sym *dynsym;
  uint64_t dyn_count;
  char *dynstr;

  Elf64_Rela *rela;
  int rela_count;
} ELFInfo;

ELFInfo *init_elf(Arena *arena);

static inline uint8_t read_byte(const uint8_t *buf, size_t offset) {
  return *(buf + offset);
}

static inline uint16_t read_word(const uint8_t *buf, size_t offset,
                                 bool is_little_endian) {
  const uint8_t *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8);

  return (p[0] << 8) | p[1];
}

static inline uint32_t read_dword(const uint8_t *buf, size_t offset,
                                  bool is_little_endian) {
  const uint8_t *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);

  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static inline uint64_t read_qword(const uint8_t *buf, size_t offset,
                                  bool is_little_endian) {
  const uint8_t *p = buf + offset;

  if (is_little_endian)
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);

  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

#endif // ELF_UTILS_H
