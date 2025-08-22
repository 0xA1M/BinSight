#include <stdio.h>

#include "core/error.h"
#include "core/mem.h"
#include "formats/elf/elf_utils.h"

ELFInfo *init_elf(Arena *arena) {
  ELFInfo *elf = arena_alloc(arena, sizeof(ELFInfo));
  ASSERT_RET_VAL(elf != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                 "Failed to allocate memory for ELFInfo from arena");

  return elf;
}

int find_shdr(const Elf64_Shdr *shdrs, const uint64_t shnum,
              uint32_t target_type) {
  ASSERT_RET_VAL(shdrs != NULL, -1, ERR_ARG_NULL,
                 "Section headers pointer is NULL");
  ASSERT_RET_VAL(shnum > 0, -1, ERR_ARG_INVALID,
                 "Number of section headers cannot be zero");

  for (size_t i = 0; i < shnum; i++)
    if (shdrs[i].sh_type == target_type)
      return (int)i;

  return -1;
}

int find_phdr(const Elf64_Phdr *phdrs, const uint64_t phnum,
              uint32_t target_type) {
  ASSERT_RET_VAL(phdrs != NULL, -1, ERR_ARG_NULL,
                 "Program headers pointer is NULL");
  ASSERT_RET_VAL(phnum > 0, -1, ERR_ARG_INVALID,
                 "Number of program headers cannot be zero");

  for (size_t i = 0; i < phnum; i++)
    if (phdrs[i].p_type == target_type)
      return (int)i;

  return -1;
}
