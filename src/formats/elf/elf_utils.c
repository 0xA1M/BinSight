#include "core/error.h"

#include "formats/elf/elf_utils.h"

ELFInfo *init_elf(Arena *arena) {
  ELFInfo *elf = arena_alloc(arena, sizeof(ELFInfo));
  ASSERT_RET_VAL(arena, elf != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                 "Failed to allocate memory for ELFInfo from arena");

  return elf;
}

const Elf64_Shdr *elf_get_section_by_type(const ELFShdrs *shdrs,
                                          uint32_t target_type) {
  if (shdrs == NULL || shdrs->headers == NULL)
    return NULL;

  for (uint16_t i = 0; i < shdrs->count; i++)
    if (shdrs->headers[i].sh_type == target_type)
      return &shdrs->headers[i];

  return NULL;
}

const Elf64_Phdr *elf_get_segment_by_type(const ELFPhdrs *phdrs,
                                          uint32_t target_type) {
  if (phdrs == NULL || phdrs->headers == NULL)
    return NULL;

  for (uint16_t i = 0; i < phdrs->count; i++)
    if (phdrs->headers[i].p_type == target_type)
      return &phdrs->headers[i];

  return NULL;
}
