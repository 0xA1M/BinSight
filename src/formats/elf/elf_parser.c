#include <elf.h>
#include <string.h>

#include "core/mem.h"
#include "core/reader.h"
#include "formats/elf/elf_parser.h"
#include "formats/elf/elf_utils.h"

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
  CHECK(reader->arena,
        elf->shdrs.strtab_off + elf->shdrs.strtab.len <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Section header string table is out of bounds");

  const Elf64_Shdr *shstrtab_hdr = &elf->shdrs.headers[elf->shdrs.strtab_ndx];
  elf->shdrs.strtab_off = shstrtab_hdr->sh_offset;

  uint64_t len = shstrtab_hdr->sh_size;
  const char *str = (const char *)(reader->data + elf->shdrs.strtab_off);
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

  if (elf->dynamic.count > 0) {
    elf->dynamic.entries = (Elf64_Dyn *)arena_alloc_array(
        reader->arena, elf->dynamic.count, sizeof(Elf64_Dyn));
    CHECK(reader->arena, elf->dynamic.entries != NULL, ERR_MEM_ALLOC_FAILED,
          "Failed to allocate for dynamic entries");

    RET_IF_ERR(parse_dynamic_entries(reader, elf));
  }

  return BERR_OK;
}

static BError parse_tables(Reader *reader, ELFInfo *elf) {
  /* Parse Section Header String Table */
  elf->shdrs.strtab_ndx = elf->ehdr->e_shstrndx;
  RET_IF_ERR(parse_strtab(reader, elf));

  /* Parse Symbol Tables using the DRY helper */
  RET_IF_ERR(parse_symbols_table(reader, elf, SHT_SYMTAB, &elf->symtab));
  RET_IF_ERR(parse_symbols_table(reader, elf, SHT_DYNSYM, &elf->dynsym));

  /* Parse Dynamic Section */
  RET_IF_ERR(parse_dynamic_table(reader, elf));

  return BERR_OK;
}

// Parse mascellanous data
static BError parse_elf_interp(Reader *reader, ELFInfo *elf) {
  const Elf64_Phdr *interp = elf_get_segment_by_type(&elf->phdrs, PT_INTERP);
  if (interp == NULL) {
    memset(&elf->interp, 0, sizeof(String));
    return BERR_OK;
  }

  CHECK(reader->arena, interp->p_offset + interp->p_memsz <= reader->size,
        ERR_FORMAT_OUT_OF_BOUNDS,
        "Interpreter segment is out of binary bounds.");

  uint64_t len = interp->p_memsz;
  const char *str = (const char *)(reader->data + interp->p_offset);
  elf->interp = string_new(reader->arena, str, len);

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
  RET_IF_ERR(parse_elf_interp(&reader, elf));

  return BERR_OK;
}
