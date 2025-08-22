#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/binary.h"
#include "core/error.h"
#include "core/mem.h"
#include "core/utils.h"
#include "formats/elf/elf_parser.h"
#include "formats/elf/elf_utils.h"

static BError parse_elf_hdr(Elf64_Ehdr *header, const uint8_t *buffer,
                            const BinaryEndianness endianness,
                            const BinaryBitness bitness) {
  CHECK(buffer != NULL, ERR_ARG_NULL, "Buffer pointer is NULL");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");
  CHECK(endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  // Copy the magic bytes (EI_NIDENT = 16)
  memcpy(header->e_ident, buffer, EI_NIDENT);

  bool is_little_endian = endianness == ENDIANNESS_LITTLE ? true : false;
  size_t offset = EI_NIDENT;

  READ_FIELD_WORD(header, e_type, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_machine, buffer, offset, is_little_endian);
  READ_FIELD_DWORD(header, e_version, buffer, offset, is_little_endian);

  READ_FIELD_32_64(header, e_entry, buffer, offset, is_little_endian, bitness);
  READ_FIELD_32_64(header, e_phoff, buffer, offset, is_little_endian, bitness);
  READ_FIELD_32_64(header, e_shoff, buffer, offset, is_little_endian, bitness);

  READ_FIELD_DWORD(header, e_flags, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_ehsize, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_phentsize, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_phnum, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_shentsize, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_shnum, buffer, offset, is_little_endian);
  READ_FIELD_WORD(header, e_shstrndx, buffer, offset, is_little_endian);

  return BERR_OK;
}

static BError parse_elf_phdr(Elf64_Phdr *p_header, const uint8_t *buffer,
                             const bool is_little_endian,
                             const BinaryBitness bitness) {
  CHECK(p_header != NULL, ERR_ARG_NULL, "Program header pointer is NULL");
  CHECK(buffer != NULL, ERR_ARG_NULL, "Buffer pointer is NULL");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");

  size_t offset = 0;
  READ_FIELD_DWORD(p_header, p_type, buffer, offset, is_little_endian);

  // We cannot use READ_FIELD_32_64 because the order of the headers differ
  // between 32bits and 64bits ELFs
  if (bitness == BITNESS_32) {
    READ_FIELD_DWORD(p_header, p_offset, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(p_header, p_vaddr, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(p_header, p_paddr, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(p_header, p_filesz, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(p_header, p_memsz, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(p_header, p_flags, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(p_header, p_align, buffer, offset, is_little_endian);
  } else if (bitness == BITNESS_64) {
    READ_FIELD_DWORD(p_header, p_flags, buffer, offset, is_little_endian);

    READ_FIELD_QWORD(p_header, p_offset, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(p_header, p_vaddr, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(p_header, p_paddr, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(p_header, p_filesz, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(p_header, p_memsz, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(p_header, p_align, buffer, offset, is_little_endian);
  }

  return BERR_OK;
}

static BError parse_elf_phdrs(Elf64_Phdr *phdrs, uint64_t phnum,
                              const uint16_t phentsize, uint64_t phoff,
                              uint8_t *data, size_t size,
                              const BinaryEndianness endianness,
                              const BinaryBitness bitness) {
  CHECK(phdrs != NULL, ERR_ARG_NULL, "Program headers pointer is NULL");
  CHECK(phnum > 0, ERR_ARG_INVALID, "Number of program headers cannot be zero");
  CHECK(phentsize > 0, ERR_ARG_INVALID,
        "Program header entry size cannot be zero");
  CHECK(phoff > 0, ERR_ARG_INVALID, "Program header offset cannot be zero");
  CHECK(data != NULL, ERR_ARG_NULL, "Data buffer pointer is NULL");
  CHECK(size > 0, ERR_ARG_INVALID, "Data buffer size cannot be zero");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");
  CHECK(endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  bool is_little_endian = endianness == ENDIANNESS_LITTLE ? true : false;
  for (size_t i = 0; i < phnum; i++) {
    size_t offset = phoff + i * phentsize;
    CHECK(offset + phentsize <= size, ERR_FORMAT_BAD_OFFSET_SIZE,
          "Program header %zu is out of bounds (offset: %zu, size: %hu, "
          "buf_size: %zu)",
          i, offset, phentsize, size);

    RET_IF_ERR(
        parse_elf_phdr(&phdrs[i], data + offset, is_little_endian, bitness));
  }

  return BERR_OK;
}

static BError parse_elf_shdr(Elf64_Shdr *s_header, const uint8_t *buffer,
                             const bool is_little_endian,
                             const BinaryBitness bitness) {
  CHECK(s_header != NULL, ERR_ARG_NULL, "Section header pointer is NULL");
  CHECK(buffer != NULL, ERR_ARG_NULL, "Buffer pointer is NULL");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");

  size_t offset = 0;
  READ_FIELD_DWORD(s_header, sh_name, buffer, offset, is_little_endian);
  READ_FIELD_DWORD(s_header, sh_type, buffer, offset, is_little_endian);

  READ_FIELD_32_64(s_header, sh_flags, buffer, offset, is_little_endian,
                   bitness);
  READ_FIELD_32_64(s_header, sh_addr, buffer, offset, is_little_endian,
                   bitness);
  READ_FIELD_32_64(s_header, sh_offset, buffer, offset, is_little_endian,
                   bitness);
  READ_FIELD_32_64(s_header, sh_size, buffer, offset, is_little_endian,
                   bitness);

  READ_FIELD_DWORD(s_header, sh_link, buffer, offset, is_little_endian);
  READ_FIELD_DWORD(s_header, sh_info, buffer, offset, is_little_endian);

  READ_FIELD_32_64(s_header, sh_addralign, buffer, offset, is_little_endian,
                   bitness);
  READ_FIELD_32_64(s_header, sh_entsize, buffer, offset, is_little_endian,
                   bitness);

  return BERR_OK;
}

static BError parse_elf_shdrs(Elf64_Shdr *shdrs, uint64_t shnum,
                              const uint16_t shentsize, uint64_t shoff,
                              uint8_t *data, size_t size,
                              const BinaryEndianness endianness,
                              const BinaryBitness bitness) {
  CHECK(shdrs != NULL, ERR_ARG_NULL, "Section headers pointer is NULL");
  CHECK(shnum > 0, ERR_ARG_INVALID, "Number of section headers cannot be zero");
  CHECK(shentsize > 0, ERR_ARG_INVALID,
        "Section header entry size cannot be zero");
  CHECK(shoff > 0, ERR_ARG_INVALID, "Section header offset cannot be zero");
  CHECK(data != NULL, ERR_ARG_NULL, "Data buffer pointer is NULL");
  CHECK(size > 0, ERR_ARG_INVALID, "Data buffer size cannot be zero");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");
  CHECK(endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  bool is_little_endian = endianness == ENDIANNESS_LITTLE ? true : false;

  for (size_t i = 0; i < shnum; i++) {
    size_t offset = shoff + i * shentsize;
    CHECK(offset + shentsize <= size, ERR_FORMAT_BAD_OFFSET_SIZE,
          "Section header %zu is out of bounds (offset: %zu, size: %hu, "
          "buf_size: %zu)",
          i, offset, shentsize, size);

    RET_IF_ERR(
        parse_elf_shdr(&shdrs[i], data + offset, is_little_endian, bitness));
  }

  return BERR_OK;
}

static BError parse_elf_shstrtab(ELFInfo *elf, BinaryFile *bin) {
  CHECK(elf->shdrs != NULL, ERR_ARG_NULL, "Section headers pointer is NULL");
  CHECK(elf->shstrndx <= elf->shnum, ERR_FORMAT_BAD_INDEX,
        "Section header string table index (%u) is out of bounds (max %lu)",
        elf->shstrndx, elf->shnum);

  const Elf64_Shdr *shstrtab_hdr = &elf->shdrs[elf->shstrndx];
  elf->shstrtab_off = shstrtab_hdr->sh_offset;
  elf->shstrtab_size = shstrtab_hdr->sh_size;

  // Validate string table bounds
  CHECK(elf->shstrtab_off + elf->shstrtab_size <= bin->size,
        ERR_FORMAT_BAD_OFFSET_SIZE, "String table section is out of bounds");

  elf->shstrtab = (const char *)arena_alloc(bin->arena, elf->shstrtab_size);
  CHECK(elf->shstrtab != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for section string table");

  memcpy((char *)elf->shstrtab, bin->data + elf->shstrtab_off,
         elf->shstrtab_size);
  return BERR_OK;
}

static BError parse_elf_sym(Elf64_Sym *sym_ent, const uint8_t *buffer,
                            const bool is_little_endian,
                            const BinaryBitness bitness) {
  CHECK(sym_ent != NULL, ERR_ARG_NULL, "Symbol entry pointer is NULL");
  CHECK(buffer != NULL, ERR_ARG_NULL, "Buffer pointer is NULL");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");

  size_t offset = 0;
  READ_FIELD_DWORD(sym_ent, st_name, buffer, offset, is_little_endian);

  if (bitness == BITNESS_32) {
    READ_FIELD_DWORD(sym_ent, st_value, buffer, offset, is_little_endian);
    READ_FIELD_DWORD(sym_ent, st_size, buffer, offset, is_little_endian);
    READ_FIELD_BYTE(sym_ent, st_info, buffer, offset);
    READ_FIELD_BYTE(sym_ent, st_other, buffer, offset);
    READ_FIELD_WORD(sym_ent, st_shndx, buffer, offset, is_little_endian);
  } else if (bitness == BITNESS_64) {
    READ_FIELD_BYTE(sym_ent, st_info, buffer, offset);
    READ_FIELD_BYTE(sym_ent, st_other, buffer, offset);
    READ_FIELD_WORD(sym_ent, st_shndx, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(sym_ent, st_value, buffer, offset, is_little_endian);
    READ_FIELD_QWORD(sym_ent, st_size, buffer, offset, is_little_endian);
  }

  return BERR_OK;
}

static BError parse_elf_syms(Elf64_Sym *symtab, uint64_t sym_count,
                             const uint16_t entsize, uint64_t off,
                             uint8_t *data, size_t size,
                             const BinaryEndianness endianness,
                             const BinaryBitness bitness) {
  CHECK(symtab != NULL, ERR_ARG_NULL, "Symbol table pointer is NULL");
  CHECK(sym_count > 0, ERR_ARG_INVALID, "Symbol count cannot be zero");
  CHECK(entsize > 0, ERR_ARG_INVALID, "Entry size cannot be zero");
  CHECK(off > 0, ERR_ARG_INVALID, "Offset cannot be zero");
  CHECK(data != NULL, ERR_ARG_NULL, "Data buffer pointer is NULL");
  CHECK(size > 0, ERR_ARG_INVALID, "Data buffer size cannot be zero");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");
  CHECK(endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  bool is_little_endian = endianness == ENDIANNESS_LITTLE ? true : false;

  for (size_t i = 0; i < sym_count; i++) {
    size_t offset = off + i * entsize;
    CHECK(offset + entsize <= size, ERR_FORMAT_BAD_OFFSET_SIZE,
          "Symbol table entry %zu is out of bounds (offset: %zu, size: %hu, "
          "buf_size: %zu)",
          i, offset, entsize, size);

    RET_IF_ERR(
        parse_elf_sym(&symtab[i], data + offset, is_little_endian, bitness));
  }

  return BERR_OK;
}

static BError parse_elf_static_syms(ELFInfo *elf, BinaryFile *bin) {
  int symtab_ndx = find_shdr(elf->shdrs, elf->shnum, SHT_SYMTAB);
  if (symtab_ndx == -1) {
    elf->symtab = NULL;
    elf->sym_count = 0;
    elf->strtab = NULL;
    elf->strtab_size = 0;
    return BERR_OK;
  }
  CHECK((uint64_t)symtab_ndx < elf->shnum, ERR_FORMAT_BAD_INDEX,
        "Static symbol table index (%d) is out of section header bounds (max "
        "%lu)",
        symtab_ndx, elf->shnum - 1);

  Elf64_Shdr *symtab = &elf->shdrs[symtab_ndx];
  CHECK(symtab->sh_link < elf->shnum, ERR_FORMAT_BAD_INDEX,
        "Static symbol table string table link (%u) is out of section header "
        "bounds (max %lu)",
        symtab->sh_link, elf->shnum - 1);
  CHECK(symtab->sh_offset + symtab->sh_size <= bin->size,
        ERR_FORMAT_BAD_OFFSET_SIZE,
        "Static symbol table section is out of binary bounds");

  if (symtab->sh_link == SHN_UNDEF) {
    elf->strtab = NULL;
    elf->strtab_size = 0;
  } else {
    Elf64_Shdr *strtab = &elf->shdrs[symtab->sh_link];
    CHECK(strtab->sh_type == SHT_STRTAB, ERR_FORMAT_INVALID_FIELD,
          "Section linked by static symbol table is not a string table");
    CHECK(strtab->sh_size + strtab->sh_offset <= bin->size,
          ERR_FORMAT_BAD_OFFSET_SIZE,
          "Static symbol string table section is out of binary bounds");

    elf->strtab_size = strtab->sh_size;
    elf->strtab =
        arena_strdup(bin->arena, (const char *)(bin->data + strtab->sh_offset),
                     strtab->sh_size);
    CHECK(elf->strtab != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to duplicate static symbol string table");
  }

  if (symtab->sh_entsize == 0 && symtab->sh_size > 0)
    return berr_new(ERR_FORMAT_INVALID_FIELD,
                    "Static symbol table has non-zero size but zero entry size",
                    __FILE__, __LINE__, __func__);

  if (symtab->sh_entsize > 0)
    elf->sym_count = symtab->sh_size / symtab->sh_entsize;
  else
    elf->sym_count = 0;

  elf->symtab = (Elf64_Sym *)arena_alloc_array(bin->arena, elf->sym_count,
                                               sizeof(Elf64_Sym));
  CHECK(elf->symtab != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for static symbol table");

  RET_IF_ERR(parse_elf_syms(elf->symtab, elf->sym_count, symtab->sh_entsize,
                            symtab->sh_offset, bin->data, bin->size,
                            bin->endianness, bin->bitness));

  return BERR_OK;
}

static BError parse_elf_dynamic_syms(ELFInfo *elf, BinaryFile *bin) {
  int dynsym_ndx = find_shdr(elf->shdrs, elf->shnum, SHT_DYNSYM);
  if (dynsym_ndx == -1) {
    elf->dynsym = NULL;
    elf->dyn_count = 0;
    elf->dynstr = NULL;
    elf->dynstr_size = 0;
    return BERR_OK;
  }

  CHECK((uint64_t)dynsym_ndx < elf->shnum, ERR_FORMAT_BAD_INDEX,
        "Dynamic symbol table index (%d) is out of section header bounds (max "
        "%lu)",
        dynsym_ndx, elf->shnum - 1);

  Elf64_Shdr *dynsym = &elf->shdrs[dynsym_ndx];
  CHECK(dynsym->sh_link < elf->shnum, ERR_FORMAT_BAD_INDEX,
        "Dynamic symbol table string table link (%u) is out of section header "
        "bounds (max %lu)",
        dynsym->sh_link, elf->shnum - 1);
  CHECK(dynsym->sh_offset + dynsym->sh_size <= bin->size,
        ERR_FORMAT_BAD_OFFSET_SIZE,
        "Dynamic symbol table section is out of binary bounds");

  if (dynsym->sh_link == SHN_UNDEF) { // No associated string table
    elf->dynstr = NULL;
    elf->dynstr_size = 0;
  } else {
    Elf64_Shdr *dynstr = &elf->shdrs[dynsym->sh_link];
    CHECK(dynstr->sh_type == SHT_STRTAB, ERR_FORMAT_INVALID_FIELD,
          "Section linked by dynamic symbol table is not a string table");
    CHECK(dynstr->sh_size + dynstr->sh_offset <= bin->size,
          ERR_FORMAT_BAD_OFFSET_SIZE,
          "Dynamic symbol string table section is out of binary bounds");

    elf->dynstr_size = dynstr->sh_size;
    elf->dynstr =
        arena_strdup(bin->arena, (const char *)(bin->data + dynstr->sh_offset),
                     dynstr->sh_size);
    CHECK(elf->dynstr != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to duplicate dynamic symbol string table");
  }

  if (dynsym->sh_entsize == 0 && dynsym->sh_size > 0) {
    return berr_new(
        ERR_FORMAT_INVALID_FIELD,
        "Dynamic symbol table has non-zero size but zero entry size", __FILE__,
        __LINE__, __func__);
  }

  if (dynsym->sh_entsize > 0) {
    elf->dyn_count = dynsym->sh_size / dynsym->sh_entsize;
  } else {
    elf->dyn_count = 0;
  }

  elf->dynsym = (Elf64_Sym *)arena_alloc_array(bin->arena, elf->dyn_count,
                                               sizeof(Elf64_Sym));
  CHECK(elf->dynsym != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for dynamic symbol table");

  RET_IF_ERR(parse_elf_syms(elf->dynsym, elf->dyn_count, dynsym->sh_entsize,
                            dynsym->sh_offset, bin->data, bin->size,
                            bin->endianness, bin->bitness));

  return BERR_OK;
}

static BError parse_elf_dynamic_entry(Elf64_Dyn *dyn_ent, const uint8_t *buffer,
                                      const bool is_little_endian,
                                      const BinaryBitness bitness) {
  CHECK(dyn_ent != NULL, ERR_ARG_NULL, "Dynamic entry pointer is NULL");
  CHECK(buffer != NULL, ERR_ARG_NULL, "Buffer pointer is NULL");
  CHECK(bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");

  size_t offset = 0;

  if (bitness == BITNESS_32) {
    READ_FIELD_DWORD(dyn_ent, d_tag, buffer, offset, is_little_endian);

    // The d_un entry of Elf64_Dyn is a union
    READ_FIELD_DWORD(dyn_ent, d_un.d_val, buffer, offset, is_little_endian);
  } else if (bitness == BITNESS_64) {
    READ_FIELD_QWORD(dyn_ent, d_tag, buffer, offset, is_little_endian);

    // The d_un entry of Elf64_Dyn is a union
    READ_FIELD_QWORD(dyn_ent, d_un.d_val, buffer, offset, is_little_endian);
  }

  return BERR_OK;
}

static BError parse_elf_dynamic_table(ELFInfo *elf, BinaryFile *bin) {
  CHECK(elf != NULL, ERR_ARG_NULL, "ELFInfo pointer is NULL");
  CHECK(bin != NULL, ERR_ARG_NULL, "BinaryFile pointer is NULL");
  CHECK(elf->dynamic != NULL, ERR_ARG_NULL, "Dynamic entries pointer is NULL");
  CHECK(elf->dynamic_count > 0, ERR_ARG_INVALID,
        "Dynamic entry count cannot be zero");
  CHECK(bin->data != NULL, ERR_ARG_NULL, "Binary data pointer is NULL");
  CHECK(bin->size > 0, ERR_ARG_INVALID, "Binary size cannot be zero");
  CHECK(bin->bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");
  CHECK(bin->endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  bool is_little_endian = bin->endianness == ENDIANNESS_LITTLE ? true : false;

  for (size_t i = 0; i < elf->dynamic_count; i++) {
    size_t offset = elf->dynamic_off + i * elf->dynamic_entsz;
    CHECK(offset + elf->dynamic_entsz <= bin->size, ERR_FORMAT_BAD_OFFSET_SIZE,
          "Dynamic table entry %zu is out of bounds (offset: %zu, size: %zu, "
          "buf_size: %zu)",
          i, offset, elf->dynamic_entsz, bin->size);

    RET_IF_ERR(parse_elf_dynamic_entry(&elf->dynamic[i], bin->data + offset,
                                       is_little_endian, bin->bitness));
  }

  return BERR_OK;
}

BError parse_elf(BinaryFile *bin, ELFInfo *elf) {
  CHECK(bin != NULL, ERR_ARG_NULL, "BinaryFile pointer is NULL");
  CHECK(elf != NULL, ERR_ARG_NULL, "ELFInfo pointer is NULL");
  CHECK(bin->data != NULL, ERR_ARG_NULL, "Binary data pointer is NULL");
  CHECK(bin->size > 0, ERR_ARG_INVALID, "Binary size is zero");
  CHECK(bin->bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID, "Unknown bitness");
  CHECK(bin->endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  CHECK(bin->size >= EI_NIDENT, ERR_FORMAT_HEADER_TOO_SMALL,
        "Buffer too small to contain ELF identification");

  size_t expected_ehdr_size =
      (bin->bitness == BITNESS_32) ? sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);
  CHECK(bin->size >= expected_ehdr_size, ERR_FORMAT_HEADER_TOO_SMALL,
        "Buffer too small to contain ELF header");

  /* Parse ELF Header */
  elf->ehdr = (Elf64_Ehdr *)arena_alloc(bin->arena, sizeof(Elf64_Ehdr));
  CHECK(elf->ehdr != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for ELF header");

  RET_IF_ERR(
      parse_elf_hdr(elf->ehdr, bin->data, bin->endianness, bin->bitness));

  CHECK((bin->bitness == BITNESS_32 &&
         elf->ehdr->e_ehsize == sizeof(Elf32_Ehdr)) ||
            (bin->bitness == BITNESS_64 &&
             elf->ehdr->e_ehsize == sizeof(Elf64_Ehdr)),
        ERR_FORMAT_HEADER_MISMATCH, "ELF header size mismatch for bitness");

  bin->is_pie = elf->ehdr->e_type == ET_DYN;

  /* Parse Program Headers */
  elf->phnum = elf->ehdr->e_phnum;
  elf->phoff = elf->ehdr->e_phoff;
  elf->phentsize = elf->ehdr->e_phentsize;

  // Sanity check
  CHECK(!(elf->phnum > 0 &&
          (elf->phoff + (uint64_t)elf->phnum * elf->phentsize) > bin->size),
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Program header table is out of binary bounds.");

  CHECK(!(elf->phnum > 0 && elf->phentsize == 0), ERR_FORMAT_INVALID_FIELD,
        "Program header entry size is zero with non-zero program headers.");

  elf->phdrs = (Elf64_Phdr *)arena_alloc_array(bin->arena, elf->phnum,
                                               sizeof(Elf64_Phdr));
  CHECK(elf->phdrs != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for program headers");

  RET_IF_ERR(parse_elf_phdrs(elf->phdrs, elf->phnum, elf->phentsize, elf->phoff,
                             bin->data, bin->size, bin->endianness,
                             bin->bitness));

  /* Parse Section Headers */
  elf->shnum = elf->ehdr->e_shnum;
  elf->shoff = elf->ehdr->e_shoff;
  elf->shentsize = elf->ehdr->e_shentsize;

  // Sanity check
  CHECK(!(elf->shnum > 0 &&
          (elf->shoff + (uint64_t)elf->shnum * elf->shentsize) > bin->size),
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Section header table is out of binary bounds.");

  CHECK(!(elf->shnum > 0 && elf->shentsize == 0), ERR_FORMAT_INVALID_FIELD,
        "Section header entry size is zero with non-zero section headers.");

  elf->shdrs = (Elf64_Shdr *)arena_alloc_array(bin->arena, elf->shnum,
                                               sizeof(Elf64_Shdr));
  CHECK(elf->shdrs != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate memory for section headers");

  RET_IF_ERR(parse_elf_shdrs(elf->shdrs, elf->shnum, elf->shentsize, elf->shoff,
                             bin->data, bin->size, bin->endianness,
                             bin->bitness));

  /* Parse String Table for Section Headers */
  elf->shstrndx = elf->ehdr->e_shstrndx;
  CHECK(!(elf->shstrndx >= elf->shnum && elf->shnum > 0), ERR_FORMAT_BAD_INDEX,
        "Section header string table index is out of bounds.");

  RET_IF_ERR(parse_elf_shstrtab(elf, bin));

  /* Parse Static/Dynamic Symbols */
  RET_IF_ERR(parse_elf_static_syms(elf, bin));
  RET_IF_ERR(parse_elf_dynamic_syms(elf, bin));

  /* Parse the Interpreter */
  int interp_ndx = find_phdr(elf->phdrs, elf->phnum, PT_INTERP);
  if (interp_ndx == -1) {
    elf->interpreter = NULL;
    elf->interp_str_size = 0;
  } else {
    Elf64_Phdr *interp = &elf->phdrs[interp_ndx];
    CHECK(!(interp->p_offset + interp->p_memsz > bin->size),
          ERR_FORMAT_OUT_OF_BOUNDS,
          "Interpreter segment is out of binary bounds.");

    elf->interpreter =
        arena_strdup(bin->arena, (const char *)(bin->data + interp->p_offset),
                     interp->p_memsz);
    CHECK(elf->interpreter != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate memory for interpreter string");

    elf->interp_str_size = interp->p_memsz;
  }

  /* Parse Dynamic */
  int dyn_ndx = find_shdr(elf->shdrs, elf->shnum, SHT_DYNAMIC);
  if (dyn_ndx == -1) {
    elf->dynamic = NULL;
    elf->dynamic_count = 0;
    elf->dynamic_off = 0;
    elf->dynamic_entsz = 0;
  } else {

    Elf64_Shdr *dyn = &elf->shdrs[dyn_ndx];
    CHECK(!(dyn->sh_entsize == 0 && dyn->sh_size > 0), ERR_FORMAT_INVALID_FIELD,
          "Dynamic section has size but zero entry size.");

    CHECK(!(dyn->sh_entsize > 0 && dyn->sh_size % dyn->sh_entsize != 0),
          ERR_FORMAT_CORRUPT_DATA,
          "Dynamic section size not multiple of entry size.");
    CHECK(!(dyn->sh_offset + dyn->sh_size > bin->size),
          ERR_FORMAT_OUT_OF_BOUNDS, "Dynamic section is out of binary bounds.");

    elf->dynamic_count = dyn->sh_size / dyn->sh_entsize;
    elf->dynamic_off = dyn->sh_offset;
    elf->dynamic_entsz = dyn->sh_entsize;

    if (elf->dynamic_count == 0) {
      elf->dynamic = NULL;
    } else {
      elf->dynamic = (Elf64_Dyn *)arena_alloc_array(
          bin->arena, elf->dynamic_count, sizeof(Elf64_Dyn));
      CHECK(elf->dynamic != NULL, ERR_MEM_ALLOC_FAILED,
            "Failed to allocate memory for dynamic entries");
    }

    RET_IF_ERR(parse_elf_dynamic_table(elf, bin));
  }

  // TODO: use a hash table instead of a linked list
  Needed_Lib **current_lib = &elf->lib;
  if (elf->dynamic != NULL) {
    for (size_t i = 0; i < elf->dynamic_count; i++) {
      Elf64_Dyn *dyn_ent = &elf->dynamic[i];

      switch (dyn_ent->d_tag) {
      case DT_NEEDED: {
        Needed_Lib *new_lib =
            (Needed_Lib *)arena_alloc(bin->arena, sizeof(Needed_Lib));
        CHECK(new_lib != NULL, ERR_MEM_ALLOC_FAILED,
              "Failed to allocate memory for Needed_Lib");

        CHECK(!(elf->dynstr == NULL || dyn_ent->d_un.d_val >= elf->dynstr_size),
              ERR_FORMAT_OUT_OF_BOUNDS,
              "DT_NEEDED string offset out of dynamic string table bounds.");

        new_lib->name =
            arena_strdup(bin->arena, elf->dynstr + dyn_ent->d_un.d_val,
                         strlen(elf->dynstr + dyn_ent->d_un.d_val));
        CHECK(new_lib->name != NULL, ERR_MEM_ALLOC_FAILED,
              "Failed to allocate memory for library name");
        new_lib->next = NULL;

        *current_lib = new_lib;
        current_lib = &new_lib->next;
        break;
      }
      case DT_SONAME: {
        CHECK(!(elf->dynstr == NULL || dyn_ent->d_un.d_val >= elf->dynstr_size),
              ERR_FORMAT_OUT_OF_BOUNDS,
              "DT_SONAME string offset out of dynamic string table bounds.");
        elf->soname =
            arena_strdup(bin->arena, elf->dynstr + dyn_ent->d_un.d_val,
                         strlen(elf->dynstr + dyn_ent->d_un.d_val));
        CHECK(elf->soname != NULL, ERR_MEM_ALLOC_FAILED,
              "Failed to allocate memory for soname");
        break;
      }
      case DT_RPATH: {
        CHECK(!(elf->dynstr == NULL || dyn_ent->d_un.d_val >= elf->dynstr_size),
              ERR_FORMAT_OUT_OF_BOUNDS,
              "DT_RPATH string offset out of dynamic string table bounds.");
        elf->rpath = arena_strdup(bin->arena, elf->dynstr + dyn_ent->d_un.d_val,
                                  strlen(elf->dynstr + dyn_ent->d_un.d_val));
        CHECK(elf->rpath != NULL, ERR_MEM_ALLOC_FAILED,
              "Failed to allocate memory for rpath");
        break;
      }
      case DT_RUNPATH: {
        CHECK(!(elf->dynstr == NULL || dyn_ent->d_un.d_val >= elf->dynstr_size),
              ERR_FORMAT_OUT_OF_BOUNDS,
              "DT_RUNPATH string offset out of dynamic string table bounds.");
        elf->runpath =
            arena_strdup(bin->arena, elf->dynstr + dyn_ent->d_un.d_val,
                         strlen(elf->dynstr + dyn_ent->d_un.d_val));
        CHECK(elf->runpath != NULL, ERR_MEM_ALLOC_FAILED,
              "Failed to allocate memory for runpath");
        break;
      }
      case DT_PLTGOT:
        elf->pltgot = dyn_ent->d_un.d_val;
        break;
      case DT_JMPREL:
        elf->jmprel = dyn_ent->d_un.d_val;
        break;
      case DT_RELA:
        elf->rela_off = dyn_ent->d_un.d_val;
        break;
      case DT_RELASZ:
        elf->rela_size = dyn_ent->d_un.d_val;
        break;
      case DT_RELAENT:
        elf->rela_entsz = dyn_ent->d_un.d_val;
        break;
      case DT_REL:
        elf->rel_off = dyn_ent->d_un.d_val;
        break;
      case DT_RELSZ:
        elf->rel_size = dyn_ent->d_un.d_val;
        break;
      case DT_RELENT:
        elf->rel_entsz = dyn_ent->d_un.d_val;
        break;
      case DT_HASH:
        elf->hash_off = dyn_ent->d_un.d_val;
        break;
      case DT_GNU_HASH:
        elf->gnu_hash_off = dyn_ent->d_un.d_val;
        break;
      case DT_NULL: // End of dynamic section
        i = elf->dynamic_count;
        break;
      default:
        // TODO: Handle other tags
        break;
      }
    }
  }

  return BERR_OK;
}
