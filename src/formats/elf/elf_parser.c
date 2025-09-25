// TODO: make the parser fail proof, parse what's valid, make other as corrupted
#include <elf.h>
#include <stdint.h>
#include <string.h>

#include "core/binary.h"
#include "core/error.h"
#include "core/mem.h"
#include "core/reader.h"
#include "core/utils.h"
#include "formats/elf/elf_parser.h"

// Parse ELF Headers
static BError parse_elf_header(Reader *reader, Elf64_Ehdr *header) {
  RET_IF_ERR(reader_read_bytes(reader, header->e_ident, EI_NIDENT));
  RET_IF_ERR(reader_read_word(reader, &header->e_type));
  RET_IF_ERR(reader_read_word(reader, &header->e_machine));
  RET_IF_ERR(reader_read_dword(reader, &header->e_version));
  RET_IF_ERR(reader_read_addr(reader, &header->e_entry));
  RET_IF_ERR(reader_read_addr(reader, &header->e_phoff));
  RET_IF_ERR(reader_read_addr(reader, &header->e_shoff));
  RET_IF_ERR(reader_read_dword(reader, &header->e_flags));
  RET_IF_ERR(reader_read_word(reader, &header->e_ehsize));
  RET_IF_ERR(reader_read_word(reader, &header->e_phentsize));
  RET_IF_ERR(reader_read_word(reader, &header->e_phnum));
  RET_IF_ERR(reader_read_word(reader, &header->e_shentsize));
  RET_IF_ERR(reader_read_word(reader, &header->e_shnum));
  RET_IF_ERR(reader_read_word(reader, &header->e_shstrndx));
  return BERR_OK;
}

static BError parse_program_header(Reader *reader, Elf64_Phdr *p_header) {
  RET_IF_ERR(reader_read_dword(reader, &p_header->p_type));

  if (reader->bitness == BITNESS_64)
    RET_IF_ERR(reader_read_dword(reader, &p_header->p_flags));

  RET_IF_ERR(reader_read_addr(reader, &p_header->p_offset));
  RET_IF_ERR(reader_read_addr(reader, &p_header->p_vaddr));
  RET_IF_ERR(reader_read_addr(reader, &p_header->p_paddr));
  RET_IF_ERR(reader_read_addr(reader, &p_header->p_filesz));
  RET_IF_ERR(reader_read_addr(reader, &p_header->p_memsz));

  if (reader->bitness == BITNESS_32)
    RET_IF_ERR(reader_read_dword(reader, &p_header->p_flags));

  RET_IF_ERR(reader_read_addr(reader, &p_header->p_align));
  return BERR_OK;
}

static BError parse_program_headers(Reader *reader, ELFPhdrs *phdrs) {
  uint64_t total_phdrs_size = 0;
  CHECK(reader->arena,
        !__builtin_mul_overflow(phdrs->count, phdrs->entry_size,
                                &total_phdrs_size),
        ERR_ARG_OUT_OF_RANGE,
        "Integer overflow when calculating total program headers size");

  CHECK(reader->arena, phdrs->offset <= reader->size, ERR_FORMAT_OUT_OF_BOUNDS,
        "Program headers offset (0x%lx) is out of bounds (size: 0x%zx)",
        phdrs->offset, reader->size);
  CHECK(reader->arena, total_phdrs_size <= reader->size - phdrs->offset,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Program headers table (size 0x%lx at offset 0x%lx) is out of bounds "
        "(file size: 0x%zx)",
        total_phdrs_size, phdrs->offset, reader->size);

  for (size_t i = 0; i < phdrs->count; i++) {
    size_t offset = phdrs->offset + (i * phdrs->entry_size);
    RET_IF_ERR(reader_seek(reader, offset));
    RET_IF_ERR(parse_program_header(reader, &phdrs->headers[i]));
  }

  return BERR_OK;
}

static BError parse_section_header(Reader *reader, Elf64_Shdr *s_header) {
  RET_IF_ERR(reader_read_dword(reader, &s_header->sh_name));
  RET_IF_ERR(reader_read_dword(reader, &s_header->sh_type));
  RET_IF_ERR(reader_read_addr(reader, &s_header->sh_flags));
  RET_IF_ERR(reader_read_addr(reader, &s_header->sh_addr));
  RET_IF_ERR(reader_read_addr(reader, &s_header->sh_offset));
  RET_IF_ERR(reader_read_addr(reader, &s_header->sh_size));
  RET_IF_ERR(reader_read_dword(reader, &s_header->sh_link));
  RET_IF_ERR(reader_read_dword(reader, &s_header->sh_info));
  RET_IF_ERR(reader_read_addr(reader, &s_header->sh_addralign));
  RET_IF_ERR(reader_read_addr(reader, &s_header->sh_entsize));
  return BERR_OK;
}

static BError parse_section_headers(Reader *reader, ELFShdrs *shdrs) {
  uint64_t total_shdrs_size = 0;
  CHECK(reader->arena,
        !__builtin_mul_overflow(shdrs->count, shdrs->entry_size,
                                &total_shdrs_size),
        ERR_ARG_OUT_OF_RANGE,
        "Integer overflow when calculating total section headers size");

  CHECK(reader->arena, shdrs->offset <= reader->size, ERR_FORMAT_OUT_OF_BOUNDS,
        "Section headers offset (0x%lx) is out of bounds (size: 0x%zx)",
        shdrs->offset, reader->size);
  CHECK(reader->arena, total_shdrs_size <= reader->size - shdrs->offset,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Section headers table (size 0x%lx at offset 0x%lx) is out of bounds "
        "(file size: 0x%zx)",
        total_shdrs_size, shdrs->offset, reader->size);

  for (size_t i = 0; i < shdrs->count; i++) {
    size_t offset = shdrs->offset + i * shdrs->entry_size;
    RET_IF_ERR(reader_seek(reader, offset));
    RET_IF_ERR(parse_section_header(reader, &shdrs->headers[i]));
  }

  return BERR_OK;
}

static BError parse_headers(Reader *reader, ELFInfo *elf) {
  elf->ehdr = (Elf64_Ehdr *)arena_alloc(reader->arena, sizeof(Elf64_Ehdr));
  CHECK(reader->arena, elf->ehdr != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate ELF header");
  RET_IF_ERR(parse_elf_header(reader, elf->ehdr));

  /* Parse Program Headers */
  if (elf->ehdr->e_phnum > 0) {
    elf->phdrs.count = elf->ehdr->e_phnum;
    elf->phdrs.offset = elf->ehdr->e_phoff;
    elf->phdrs.entry_size = elf->ehdr->e_phentsize;
    size_t expected_phent_size = (reader->bitness == BITNESS_32)
                                     ? sizeof(Elf32_Phdr)
                                     : sizeof(Elf64_Phdr);
    CHECK(reader->arena, elf->phdrs.entry_size == expected_phent_size,
          ERR_FORMAT_INVALID_FIELD,
          "Invalid program header size: got %lu, expected %zu",
          elf->phdrs.entry_size, expected_phent_size);

    elf->phdrs.headers = (Elf64_Phdr *)arena_alloc_array(
        reader->arena, elf->phdrs.count, sizeof(Elf64_Phdr));
    CHECK(reader->arena, elf->phdrs.headers != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate program headers");
    RET_IF_ERR(parse_program_headers(reader, &elf->phdrs));
  }

  /* Parse Section Headers */
  if (elf->ehdr->e_shnum > 0) {
    elf->shdrs.count = elf->ehdr->e_shnum;
    elf->shdrs.offset = elf->ehdr->e_shoff;
    elf->shdrs.entry_size = elf->ehdr->e_shentsize;
    size_t expected_shent_size = (reader->bitness == BITNESS_32)
                                     ? sizeof(Elf32_Shdr)
                                     : sizeof(Elf64_Shdr);
    CHECK(reader->arena, elf->shdrs.entry_size == expected_shent_size,
          ERR_FORMAT_INVALID_FIELD,
          "Invalid section header size: got %lu, expected %zu",
          elf->shdrs.entry_size, expected_shent_size);

    elf->shdrs.headers = (Elf64_Shdr *)arena_alloc_array(
        reader->arena, elf->shdrs.count, sizeof(Elf64_Shdr));
    CHECK(reader->arena, elf->shdrs.headers != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate section headers");
    RET_IF_ERR(parse_section_headers(reader, &elf->shdrs));
  }

  return BERR_OK;
}

// Parse ELF Sections & Tables
static BError parse_strtab(Reader *reader, ELFInfo *elf) {
  CHECK(reader->arena, elf->shdrs.strtab_ndx < elf->shdrs.count,
        ERR_FORMAT_BAD_INDEX,
        "Section header string table index (%u) is out of bounds (section "
        "headers count: %u)",
        elf->shdrs.strtab_ndx, elf->shdrs.count);

  const Elf64_Shdr *shstrtab_hdr = &elf->shdrs.headers[elf->shdrs.strtab_ndx];
  ASSERT_RET_VAL(reader->arena, shstrtab_hdr->sh_offset < reader->size, BERR_OK,
                 ERR_FORMAT_OUT_OF_BOUNDS,
                 "Section header string table is out of bounds, skipping!");

  CHECK(reader->arena,
        shstrtab_hdr->sh_offset + shstrtab_hdr->sh_size <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Section header string table is out of bounds");

  const char *str = (const char *)(reader->data + shstrtab_hdr->sh_offset);
  uint64_t len = shstrtab_hdr->sh_size;

  elf->shdrs.strtab_off = shstrtab_hdr->sh_offset;
  elf->shdrs.strtab = string_new(reader->arena, str, len);

  return BERR_OK;
}

static BError parse_symbol(Reader *reader, Elf64_Sym *sym_ent) {
  RET_IF_ERR(reader_read_dword(reader, &sym_ent->st_name));
  if (reader->bitness == BITNESS_32) {
    RET_IF_ERR(reader_read_dword(reader, (uint32_t *)&sym_ent->st_value));
    RET_IF_ERR(reader_read_dword(reader, (uint32_t *)&sym_ent->st_size));
    RET_IF_ERR(reader_read_byte(reader, &sym_ent->st_info));
    RET_IF_ERR(reader_read_byte(reader, &sym_ent->st_other));
    RET_IF_ERR(reader_read_word(reader, &sym_ent->st_shndx));
  } else {
    RET_IF_ERR(reader_read_byte(reader, &sym_ent->st_info));
    RET_IF_ERR(reader_read_byte(reader, &sym_ent->st_other));
    RET_IF_ERR(reader_read_word(reader, &sym_ent->st_shndx));
    RET_IF_ERR(reader_read_qword(reader, &sym_ent->st_value));
    RET_IF_ERR(reader_read_qword(reader, &sym_ent->st_size));
  }
  return BERR_OK;
}

static BError parse_symbols(Reader *reader, ELFSymTab *symtab) {
  uint64_t total_symbols_size = 0;
  CHECK(reader->arena,
        !__builtin_mul_overflow(symtab->count, symtab->entry_size,
                                &total_symbols_size),
        ERR_ARG_OUT_OF_RANGE,
        "Integer overflow when calculating total symbols size");

  CHECK(reader->arena, symtab->offset <= reader->size, ERR_FORMAT_OUT_OF_BOUNDS,
        "Symbol table offset (0x%lx) is out of bounds (size: 0x%zx)",
        symtab->offset, reader->size);
  CHECK(reader->arena, total_symbols_size <= reader->size - symtab->offset,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Symbol table (size 0x%lx at offset 0x%lx) is out of bounds "
        "(file size: 0x%zx)",
        total_symbols_size, symtab->offset, reader->size);

  for (size_t i = 0; i < symtab->count; i++) {
    size_t offset = symtab->offset + i * symtab->entry_size;
    RET_IF_ERR(reader_seek(reader, offset));
    RET_IF_ERR(parse_symbol(reader, &symtab->symbols[i]));
  }
  return BERR_OK;
}

static BError parse_symbols_table(Reader *reader, ELFInfo *elf,
                                  uint32_t sh_type, ELFSymTab *out) {
  const Elf64_Shdr *symtab_hdr = elf_get_section_by_type(&elf->shdrs, sh_type);
  if (symtab_hdr == NULL) {
    memset(out, 0, sizeof(ELFSymTab));
    return BERR_OK;
  }

  CHECK(reader->arena, symtab_hdr->sh_link < elf->shdrs.count,
        ERR_FORMAT_BAD_INDEX,
        "Symbol table's string table index is out of bounds");

  out->offset = symtab_hdr->sh_offset;
  out->entry_size = symtab_hdr->sh_entsize;
  out->count = symtab_hdr->sh_entsize > 0
                   ? symtab_hdr->sh_size / symtab_hdr->sh_entsize
                   : 0;

  size_t expected_sym_size =
      (reader->bitness == BITNESS_32) ? sizeof(Elf32_Sym) : sizeof(Elf64_Sym);
  CHECK(reader->arena, out->entry_size == expected_sym_size,
        ERR_FORMAT_INVALID_FIELD,
        "Invalid symtab entry size: got %lu, expected %zu", out->entry_size,
        expected_sym_size);

  if (out->count > 0) {
    Elf64_Shdr *strtab_hdr = &elf->shdrs.headers[symtab_hdr->sh_link];
    CHECK(reader->arena, strtab_hdr->sh_type == SHT_STRTAB,
          ERR_FORMAT_INVALID_FIELD,
          "Section linked from symbol table is not a string table");
    CHECK(reader->arena,
          strtab_hdr->sh_offset + strtab_hdr->sh_size <= reader->size,
          ERR_FORMAT_OUT_OF_BOUNDS, "Symbol string table is out of bounds");

    uint64_t len = strtab_hdr->sh_size;
    const char *str = (const char *)(reader->data + strtab_hdr->sh_offset);
    out->strtab = string_new(reader->arena, str, len);

    out->symbols = (Elf64_Sym *)arena_alloc_array(reader->arena, out->count,
                                                  sizeof(Elf64_Sym));
    CHECK(reader->arena, out->symbols != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate memory for symbol table");

    RET_IF_ERR(parse_symbols(reader, out));
  }

  return BERR_OK;
}

static BError parse_dynamic_entry(Reader *reader, Elf64_Dyn *dyn_ent) {
  RET_IF_ERR(reader_read_addr(reader, (uint64_t *)&dyn_ent->d_tag));
  RET_IF_ERR(reader_read_addr(reader, (uint64_t *)&dyn_ent->d_un.d_val));
  return BERR_OK;
}

static BError parse_dynamic_entries(Reader *reader, ELFInfo *elf) {
  uint64_t total_dynamic_size = 0;
  CHECK(reader->arena,
        !__builtin_mul_overflow(elf->dynamic.count, elf->dynamic.entry_size,
                                &total_dynamic_size),
        ERR_ARG_OUT_OF_RANGE,
        "Integer overflow when calculating total symbols size");

  CHECK(reader->arena, elf->dynamic.offset <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Dynamic section offset (0x%lx) is out of bounds (size: 0x%zx)",
        elf->dynamic.offset, reader->size);
  CHECK(reader->arena, total_dynamic_size <= reader->size - elf->dynamic.offset,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Symbol table (size 0x%lx at offset 0x%lx) is out of bounds "
        "(file size: 0x%zx)",
        total_dynamic_size, elf->dynamic.offset, reader->size);

  for (size_t i = 0; i < elf->dynamic.count; i++) {
    size_t offset = elf->dynamic.offset + i * elf->dynamic.entry_size;
    RET_IF_ERR(reader_seek(reader, offset));
    RET_IF_ERR(parse_dynamic_entry(reader, &elf->dynamic.entries[i]));
  }
  return BERR_OK;
}

static BError parse_dynamic_table(Reader *reader, ELFInfo *elf) {
  const Elf64_Shdr *dyn_hdr = elf_get_section_by_type(&elf->shdrs, SHT_DYNAMIC);
  if (dyn_hdr == NULL) {
    memset(&elf->dynamic, 0, sizeof(ELFDynTab));
    return BERR_OK;
  }

  elf->dynamic.offset = dyn_hdr->sh_offset;
  elf->dynamic.entry_size = dyn_hdr->sh_entsize;
  elf->dynamic.count =
      dyn_hdr->sh_entsize > 0 ? dyn_hdr->sh_size / dyn_hdr->sh_entsize : 0;

  size_t expected_dynamic_size =
      (reader->bitness == BITNESS_32) ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);
  CHECK(reader->arena, elf->dynamic.entry_size == expected_dynamic_size,
        ERR_FORMAT_INVALID_FIELD,
        "Invalid dynamic section entry size: got %lu, expected %zu",
        elf->dynamic.entry_size, expected_dynamic_size);

  if (elf->dynamic.count > 0) {
    elf->dynamic.entries = (Elf64_Dyn *)arena_alloc_array(
        reader->arena, elf->dynamic.count, sizeof(Elf64_Dyn));
    CHECK(reader->arena, elf->dynamic.entries != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate for dynamic entries");

    RET_IF_ERR(parse_dynamic_entries(reader, elf));
  }

  return BERR_OK;
}

static BError parse_rel_entry(Reader *reader, Elf64_Rel *rel_ent) {
  RET_IF_ERR(reader_read_addr(reader, &rel_ent->r_offset));
  RET_IF_ERR(reader_read_addr(reader, &rel_ent->r_info));
  return BERR_OK;
}

static BError parse_rela_entry(Reader *reader, Elf64_Rela *rela_ent) {
  RET_IF_ERR(reader_read_addr(reader, &rela_ent->r_offset));
  RET_IF_ERR(reader_read_addr(reader, &rela_ent->r_info));
  RET_IF_ERR(reader_read_addr(reader, (uint64_t *)&rela_ent->r_addend));
  return BERR_OK;
}

static BError parse_reloc_tab_entries(Reader *reader, ELFRelTab *rel_tab,
                                      const uint32_t sh_type) {
  uint64_t total_reloc_size = 0;
  CHECK(reader->arena,
        !__builtin_mul_overflow(rel_tab->count, rel_tab->entry_size,
                                &total_reloc_size),
        ERR_ARG_OUT_OF_RANGE,
        "Integer overflow when calculating total relocations size");

  CHECK(reader->arena, rel_tab->offset <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Relocation tables offset (0x%lx) is out of bounds (size: 0x%zx)",
        rel_tab->offset, reader->size);
  CHECK(reader->arena, total_reloc_size <= reader->size - rel_tab->offset,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Relocation table (size 0x%lx at offset 0x%lx) is out of bounds (file "
        "size: 0x%zx)",
        total_reloc_size, rel_tab->offset, reader->size);

  if (sh_type == SHT_REL) {
    rel_tab->rel_entries = (Elf64_Rel *)arena_alloc_array(
        reader->arena, rel_tab->count, sizeof(Elf64_Rel));
    CHECK(reader->arena, rel_tab->rel_entries != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate memory for REL entries");

    for (size_t i = 0; i < rel_tab->count; i++) {
      size_t offset = rel_tab->offset + rel_tab->entry_size * i;
      RET_IF_ERR(reader_seek(reader, offset));
      RET_IF_ERR(parse_rel_entry(reader, &rel_tab->rel_entries[i]));
    }
  } else { // SHT_RELA
    rel_tab->rela_entries = (Elf64_Rela *)arena_alloc_array(
        reader->arena, rel_tab->count, sizeof(Elf64_Rela));
    CHECK(reader->arena, rel_tab->rela_entries != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate memory for RELA entries");

    for (size_t i = 0; i < rel_tab->count; ++i) {
      size_t offset = rel_tab->offset + i * rel_tab->entry_size;
      RET_IF_ERR(reader_seek(reader, offset));
      RET_IF_ERR(parse_rela_entry(reader, &rel_tab->rela_entries[i]));
    }
  }

  return BERR_OK;
}

static BError parse_reloc_table(Reader *reader, ELFInfo *elf,
                                const Elf64_Shdr *reloc_hdr,
                                ELFRelTab *rel_tab) {
  if (!IS_STR_EMPTY(elf->shdrs.strtab)) {
    CHECK(reader->arena, reloc_hdr->sh_name < elf->shdrs.strtab.len,
          ERR_FORMAT_OUT_OF_BOUNDS,
          "Relocation section name offset is out of bounds");

    const char *reloc_name =
        (const char *)(elf->shdrs.strtab.str + reloc_hdr->sh_name);
    const uint64_t max_len = elf->shdrs.strtab.len - reloc_hdr->sh_name;

    rel_tab->name =
        string_new(reader->arena, reloc_name, strnlen(reloc_name, max_len));
  }

  rel_tab->sh_type = reloc_hdr->sh_type;
  rel_tab->offset = reloc_hdr->sh_offset;
  rel_tab->entry_size = reloc_hdr->sh_entsize;
  rel_tab->count = reloc_hdr->sh_entsize > 0
                       ? reloc_hdr->sh_size / reloc_hdr->sh_entsize
                       : 0;

  size_t expected_reloc_size =
      (reloc_hdr->sh_type == SHT_REL)
          ? ((reader->bitness == BITNESS_32) ? sizeof(Elf32_Rel)
                                             : sizeof(Elf64_Rel))
          : ((reader->bitness == BITNESS_32) ? sizeof(Elf32_Rela)
                                             : sizeof(Elf64_Rela));

  if (reloc_hdr->sh_entsize > 0)
    CHECK(reader->arena, rel_tab->entry_size == expected_reloc_size,
          ERR_FORMAT_INVALID_FIELD,
          "Invalid relocation entry size: got %lu, expected %zu",
          rel_tab->entry_size, expected_reloc_size);

  CHECK(reader->arena, reloc_hdr->sh_link < elf->shdrs.count,
        ERR_FORMAT_BAD_INDEX,
        "Relocation section '" STR "' has an out-of-bounds sh_link (%u)",
        (int)rel_tab->name.len, rel_tab->name.str, reloc_hdr->sh_link);

  const Elf64_Shdr *linked_shdr = &elf->shdrs.headers[reloc_hdr->sh_link];
  switch (linked_shdr->sh_type) {
  case SHT_SYMTAB:
    rel_tab->symtab = &elf->symtab;
    break;
  case SHT_DYNSYM:
    rel_tab->symtab = &elf->dynsym;
    break;
  default: // TODO: Better handling
    rel_tab->symtab = NULL;

    LOG_ERR("Relocation section '" STR "' links to a non-symbol table "
            "(type: %u)",
            (int)rel_tab->name.len, rel_tab->name.str, linked_shdr->sh_type);
    break;
  }

  if (rel_tab->count > 0)
    RET_IF_ERR(parse_reloc_tab_entries(reader, rel_tab, reloc_hdr->sh_type));

  return BERR_OK;
}

struct BError parse_reloc_tables(Reader *reader, ELFInfo *elf) {
  uint16_t reloc_count = 0;
  for (uint16_t i = 0; i < elf->shdrs.count; i++) {
    const Elf64_Shdr *shdr = &elf->shdrs.headers[i];
    if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA)
      reloc_count++;
  }

  elf->relocs.count = reloc_count;
  if (reloc_count > 0) {
    elf->relocs.tables = (ELFRelTab *)arena_alloc_array(
        reader->arena, reloc_count, sizeof(ELFRelTab));
    CHECK(reader->arena, elf->relocs.tables != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate memory for ELF relocation tables array");

    uint64_t current_reloc_ndx = 0;
    for (uint16_t i = 0; i < elf->shdrs.count; i++) {
      const Elf64_Shdr *shdr = &elf->shdrs.headers[i];
      if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA)
        RET_IF_ERR(parse_reloc_table(reader, elf, shdr,
                                     &elf->relocs.tables[current_reloc_ndx++]));
    }
  }

  return BERR_OK;
}

static BError parse_tables(Reader *reader, ELFInfo *elf) {
  /* Parse Section Header String Table */
  elf->shdrs.strtab_ndx = elf->ehdr->e_shstrndx;
  RET_IF_ERR(parse_strtab(reader, elf));

  /* Parse Symbol Tables */
  RET_IF_ERR(parse_symbols_table(reader, elf, SHT_SYMTAB, &elf->symtab));
  RET_IF_ERR(parse_symbols_table(reader, elf, SHT_DYNSYM, &elf->dynsym));

  /* Parse Dynamic Section */
  RET_IF_ERR(parse_dynamic_table(reader, elf));

  /* Parse Relocation Tables */
  RET_IF_ERR(parse_reloc_tables(reader, elf));

  return BERR_OK;
}

// Parse miscellaneous data
static BError parse_interp(Reader *reader, ELFInfo *elf) {
  const Elf64_Phdr *interp = elf_get_segment_by_type(&elf->phdrs, PT_INTERP);
  if (interp == NULL) {
    memset(&elf->interp, 0, sizeof(String));
    return BERR_OK;
  }

  CHECK(reader->arena, interp->p_filesz < reader->size,
        ERR_FORMAT_INVALID_FIELD,
        "Invalid interpreter segment size. (%lu >> %lu [actual binary size])",
        interp->p_filesz, reader->size);
  CHECK(reader->arena, interp->p_offset + interp->p_filesz <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Interpreter segment is out of binary bounds.");

  const char *str = (const char *)(reader->data + interp->p_offset);
  elf->interp = string_new(reader->arena, str, interp->p_filesz);

  return BERR_OK;
}

static BError parse_version_symbols(Reader *reader, ELFInfo *elf) {
  const Elf64_Shdr *versym_hdr =
      elf_get_section_by_type(&elf->shdrs, SHT_GNU_versym);
  if (versym_hdr == NULL) {
    memset(&elf->versym, 0, sizeof(ELFVersymTab));
    return BERR_OK;
  }

  elf->versym.offset = versym_hdr->sh_offset;
  elf->versym.count = versym_hdr->sh_size / sizeof(Elf64_Versym);

  if (elf->versym.count > 0) {
    elf->versym.entries = arena_alloc_array(reader->arena, elf->versym.count,
                                            sizeof(Elf64_Versym));
    CHECK(reader->arena, elf->versym.entries != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate %lu versym entries (section .gnu.version, size "
          "%lu bytes)",
          elf->versym.count, versym_hdr->sh_size);

    RET_IF_ERR(reader_seek(reader, elf->versym.offset));
    for (uint64_t i = 0; i < elf->versym.count; i++)
      RET_IF_ERR(reader_read_word(reader, &elf->versym.entries[i]));
  }

  return BERR_OK;
}

static BError parse_verdef_entry(Reader *reader, Elf64_Verdef *verdef_entry) {
  RET_IF_ERR(reader_read_word(reader, &verdef_entry->vd_version));
  RET_IF_ERR(reader_read_word(reader, &verdef_entry->vd_flags));
  RET_IF_ERR(reader_read_word(reader, &verdef_entry->vd_ndx));
  RET_IF_ERR(reader_read_word(reader, &verdef_entry->vd_cnt));
  RET_IF_ERR(reader_read_dword(reader, &verdef_entry->vd_hash));
  RET_IF_ERR(reader_read_dword(reader, &verdef_entry->vd_aux));
  RET_IF_ERR(reader_read_dword(reader, &verdef_entry->vd_next));
  return BERR_OK;
}

static BError parse_verdaux_entry(Reader *reader,
                                  Elf64_Verdaux *verdaux_entry) {
  RET_IF_ERR(reader_read_dword(reader, &verdaux_entry->vda_name));
  RET_IF_ERR(reader_read_dword(reader, &verdaux_entry->vda_next));
  return BERR_OK;
}

static BError parse_version_definitions(Reader *reader, ELFInfo *elf) {
  const Elf64_Shdr *verdef_hdr =
      elf_get_section_by_type(&elf->shdrs, SHT_GNU_verdef);
  if (verdef_hdr == NULL) {
    memset(&elf->verdef, 0, sizeof(ELFVerdef));
    return BERR_OK;
  }

  CHECK(reader->arena,
        verdef_hdr->sh_offset + verdef_hdr->sh_size <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Version definition header offset out of bound");
  CHECK(reader->arena,
        verdef_hdr->sh_info < verdef_hdr->sh_size / sizeof(Elf64_Verdef),
        ERR_FORMAT_INVALID_FIELD,
        "Version definition header count mismatch: got (%lu) expected (%lu)",
        verdef_hdr->sh_info, verdef_hdr->sh_size / sizeof(Elf64_Verdef));

  elf->verdef.offset = verdef_hdr->sh_offset;
  elf->verdef.count = verdef_hdr->sh_info;

  if (elf->verdef.count > 0) {
    elf->verdef.entries = (ELFVerdef **)arena_alloc_array(
        reader->arena, elf->verdef.count, sizeof(ELFVerdef *));
    CHECK(reader->arena, elf->verdef.entries != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate %lu verdef entries (section .gnu.version_d, size "
          "%lu bytes)",
          elf->verdef.count, verdef_hdr->sh_size);

    uintptr_t current_offset = verdef_hdr->sh_offset;
    uintptr_t section_end = verdef_hdr->sh_offset + verdef_hdr->sh_size;

    for (uint64_t i = 0; i < elf->verdef.count; i++) {
      CHECK(reader->arena, current_offset + sizeof(Elf64_Verdef) < section_end,
            ERR_FORMAT_OUT_OF_BOUNDS,
            "Current version definition header offset is out of bound");

      ELFVerdef *verdef =
          (ELFVerdef *)arena_alloc(reader->arena, sizeof(ELFVerdef));
      CHECK(reader->arena, verdef != NULL, ERR_MEM_ALLOC_FAILED,
            "Failed to allocate verdef entry #%lu", i);
      elf->verdef.entries[i] = verdef;

      RET_IF_ERR(reader_seek(reader, current_offset));
      RET_IF_ERR(parse_verdef_entry(reader, &verdef->verdef));

      // Get the name of the version definition
      if (!IS_STR_EMPTY(elf->dynsym.strtab) && verdef->verdef.vd_aux > 0) {
        uintptr_t temp_offset = current_offset + verdef->verdef.vd_aux;

        if (temp_offset < reader->size) {
          Elf64_Verdaux temp_verdaux = {0};
          size_t original_reader_offset = reader_get_offset(reader);

          RET_IF_ERR(reader_seek(reader, temp_offset));
          RET_IF_ERR(parse_verdaux_entry(reader, &temp_verdaux));

          if (temp_verdaux.vda_name < elf->dynsym.strtab.len) {
            const char *name = elf->dynsym.strtab.str + temp_verdaux.vda_name;
            const uint64_t max_len =
                elf->dynsym.strtab.len - temp_verdaux.vda_name;

            verdef->name =
                string_new(reader->arena, name, strnlen(name, max_len));
          }

          RET_IF_ERR(reader_seek(reader, original_reader_offset));
        }
      }

      // Parse Verdaux entries
      verdef->verdaux.count = verdef->verdef.vd_cnt;
      if (verdef->verdaux.count > 0) {
        verdef->verdaux.entries = (Elf64_Verdaux *)arena_alloc_array(
            reader->arena, verdef->verdaux.count, sizeof(Elf64_Verdaux));
        CHECK(reader->arena, verdef->verdaux.entries != NULL,
              ERR_MEM_ALLOC_FAILED,
              "Failed to allocate %hu Verdaux entries for verdef %lu",
              verdef->verdaux.count, i);

        uintptr_t verdaux_current_offset =
            current_offset + verdef->verdef.vd_aux;
        for (uint16_t j = 0; j < verdef->verdaux.count; ++j) {
          RET_IF_ERR(reader_seek(reader, verdaux_current_offset));
          RET_IF_ERR(parse_verdaux_entry(reader, &verdef->verdaux.entries[j]));

          if (verdef->verdaux.entries[j].vda_next == 0)
            break;
          verdaux_current_offset += verdef->verdaux.entries[j].vda_next;
        }
      }

      if (verdef->verdef.vd_next == 0)
        break;

      CHECK(reader->arena,
            current_offset + verdef->verdef.vd_next < section_end,
            ERR_FORMAT_OUT_OF_BOUNDS,
            "Next version definition header is out of bound");
      current_offset += verdef->verdef.vd_next;
    }
  }

  return BERR_OK;
}

static BError parse_verneed_entry(Reader *reader,
                                  Elf64_Verneed *verneed_entry) {
  RET_IF_ERR(reader_read_word(reader, &verneed_entry->vn_version));
  RET_IF_ERR(reader_read_word(reader, &verneed_entry->vn_cnt));
  RET_IF_ERR(reader_read_dword(reader, &verneed_entry->vn_file));
  RET_IF_ERR(reader_read_dword(reader, &verneed_entry->vn_aux));
  RET_IF_ERR(reader_read_dword(reader, &verneed_entry->vn_next));
  return BERR_OK;
}

static BError parse_vernaux_entry(Reader *reader,
                                  Elf64_Vernaux *vernaux_entry) {
  RET_IF_ERR(reader_read_dword(reader, &vernaux_entry->vna_hash));
  RET_IF_ERR(reader_read_word(reader, &vernaux_entry->vna_flags));
  RET_IF_ERR(reader_read_word(reader, &vernaux_entry->vna_other));
  RET_IF_ERR(reader_read_dword(reader, &vernaux_entry->vna_name));
  RET_IF_ERR(reader_read_dword(reader, &vernaux_entry->vna_next));
  return BERR_OK;
}

static BError parse_version_needs(Reader *reader, ELFInfo *elf) {
  const Elf64_Shdr *verneed_hdr =
      elf_get_section_by_type(&elf->shdrs, SHT_GNU_verneed);
  if (verneed_hdr == NULL) {
    memset(&elf->verneed, 0, sizeof(ELFVerneedTab));
    return BERR_OK;
  }

  CHECK(reader->arena,
        verneed_hdr->sh_offset + verneed_hdr->sh_size <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS, "Version needs header offset out of bound");
  CHECK(reader->arena,
        verneed_hdr->sh_info < verneed_hdr->sh_size / sizeof(Elf64_Verneed),
        ERR_FORMAT_INVALID_FIELD,
        "Version needs header count mismatch: got (%lu) expected (%lu)",
        verneed_hdr->sh_info, verneed_hdr->sh_size / sizeof(Elf64_Verneed));

  elf->verneed.offset = verneed_hdr->sh_offset;
  elf->verneed.count = verneed_hdr->sh_info;

  if (elf->verneed.count > 0) {
    elf->verneed.entries = (ELFVerneed **)arena_alloc_array(
        reader->arena, elf->verneed.count, sizeof(ELFVerneed *));
    CHECK(
        reader->arena, elf->verneed.entries != NULL, ERR_MEM_ALLOC_FAILED,
        "Failed to allocate %lu verneed entries (section .gnu.version_r, size "
        "%lu bytes)",
        elf->verneed.count, verneed_hdr->sh_size);

    uintptr_t current_offset = elf->verneed.offset;
    uintptr_t section_end = verneed_hdr->sh_offset + verneed_hdr->sh_size;

    for (uint64_t i = 0; i < elf->verneed.count; ++i) {
      CHECK(reader->arena, current_offset + sizeof(Elf64_Verneed) < section_end,
            ERR_FORMAT_OUT_OF_BOUNDS,
            "Current version needs header offset is out of bound");

      ELFVerneed *verneed =
          (ELFVerneed *)arena_alloc(reader->arena, sizeof(ELFVerneed));
      CHECK(reader->arena, verneed != NULL, ERR_MEM_ALLOC_FAILED,
            "Failed to allocate verneed entry %lu", i);
      elf->verneed.entries[i] = verneed;

      RET_IF_ERR(reader_seek(reader, current_offset));
      RET_IF_ERR(parse_verneed_entry(reader, &verneed->verneed));

      // Get the file name from the dynamic string table
      if (!IS_STR_EMPTY(elf->dynsym.strtab) &&
          verneed->verneed.vn_file < elf->dynsym.strtab.len) {
        const char *file_name =
            elf->dynsym.strtab.str + verneed->verneed.vn_file;
        const uint64_t max_len =
            elf->dynsym.strtab.len - verneed->verneed.vn_file;

        verneed->file_name =
            string_new(reader->arena, file_name, strnlen(file_name, max_len));
      }

      verneed->vernaux.count = verneed->verneed.vn_cnt;
      if (verneed->vernaux.count > 0) {
        verneed->vernaux.entries = (Elf64_Vernaux *)arena_alloc_array(
            reader->arena, verneed->vernaux.count, sizeof(Elf64_Vernaux));
        CHECK(reader->arena, verneed->vernaux.entries != NULL,
              ERR_MEM_ALLOC_FAILED,
              "Failed to allocate %hu Vernaux entries for verneed %lu",
              verneed->vernaux.count, i);

        uintptr_t vernaux_current_offset =
            current_offset + verneed->verneed.vn_aux;
        for (uint16_t j = 0; j < verneed->vernaux.count; j++) {
          RET_IF_ERR(reader_seek(reader, vernaux_current_offset));
          RET_IF_ERR(parse_vernaux_entry(reader, &verneed->vernaux.entries[j]));

          if (verneed->vernaux.entries[j].vna_next == 0)
            break;

          CHECK(reader->arena,
                current_offset + verneed->verneed.vn_next < section_end,
                ERR_FORMAT_OUT_OF_BOUNDS,
                "Next version needs header is out of bound");
          vernaux_current_offset += verneed->vernaux.entries[j].vna_next;
        }
      }

      if (verneed->verneed.vn_next == 0)
        break;
      current_offset += verneed->verneed.vn_next;
    }
  }

  return BERR_OK;
}

BError parse_elf(const Binary *bin, ELFInfo *elf) {
  CHECK(bin->arena, bin->bitness != BITNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown bitness");
  CHECK(bin->arena, bin->endianness != ENDIANNESS_UNKNOWN, ERR_ARG_INVALID,
        "Unknown endianness");

  Reader reader = create_reader(bin);

  /* Parse ELF Header */
  RET_IF_ERR(parse_headers(&reader, elf));

  /* Parse Sections & Tables */
  if (elf->shdrs.count > 0)
    RET_IF_ERR(parse_tables(&reader, elf));

  /* Miscellaneous Data */
  RET_IF_ERR(parse_interp(&reader, elf));

  RET_IF_ERR(parse_version_symbols(&reader, elf));
  RET_IF_ERR(parse_version_definitions(&reader, elf));
  RET_IF_ERR(parse_version_needs(&reader, elf));

  return BERR_OK;
}
