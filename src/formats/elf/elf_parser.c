#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/binary.h"
#include "core/mem.h"
#include "formats/elf/elf_parser.h"
#include "formats/elf/elf_utils.h"

static int parse_elf_hdr(Elf64_Ehdr *header, const uint8_t *buffer,
                         const BinaryBitness bitness) {
  if (buffer == NULL || bitness == BITNESS_UNKNOWN)
    return -1;

  // Copy the magic bytes (EI_NIDENT = 16)
  memcpy(header->e_ident, buffer, EI_NIDENT);

  bool is_little_endian = (header->e_ident[EI_DATA] == ELFDATA2LSB);
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

  return 0;
}

static int parse_elf_phdr(Elf64_Phdr *p_header, const uint8_t *buffer,
                          const bool is_little_endian,
                          const BinaryBitness bitness) {
  if (buffer == NULL || bitness == BITNESS_UNKNOWN)
    return -1;

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

  return 0;
}

static int parse_elf_shdr(Elf64_Shdr *s_header, const uint8_t *buffer,
                          const bool is_little_endian,
                          const BinaryBitness bitness) {
  if (buffer == NULL || bitness == BITNESS_UNKNOWN)
    return -1;

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

  return 0;
}

int parse_elf(BinaryFile *bin, ELFInfo *elf) {
  if (elf == NULL || bin->data == NULL || bin->size <= 0) {
    fprintf(stderr, "Invalid arguments to parse_elf\n");
    return -1;
  }

  if (bin->size < EI_NIDENT) {
    fprintf(stderr, "Buffer too small to contain ELF identification\n");
    return -1;
  }

  if ((bin->bitness == BITNESS_32 && bin->size < sizeof(Elf32_Ehdr)) ||
      (bin->bitness == BITNESS_64 && bin->size < sizeof(Elf64_Ehdr))) {
    fprintf(stderr, "Buffer too small to contain ELF header\n");
    return -1;
  }

  elf->ehdr = (Elf64_Ehdr *)arena_alloc(bin->arena, sizeof(Elf64_Ehdr));
  if (elf->ehdr == NULL)
    return -1;

  if (parse_elf_hdr(elf->ehdr, bin->data, bin->bitness) == -1)
    return -1;

  elf->phnum = elf->ehdr->e_phnum;
  elf->phoff = elf->ehdr->e_phoff;
  elf->phentsize = elf->ehdr->e_phentsize;

  elf->shnum = elf->ehdr->e_shnum;
  elf->shoff = elf->ehdr->e_shoff;
  elf->shentsize = elf->ehdr->e_shentsize;

  elf->shstrndx = elf->ehdr->e_shstrndx;

  // Allocate array of program headers
  if (elf->phnum > 0) {
    elf->phdrs = (Elf64_Phdr *)arena_alloc_array(bin->arena, elf->phnum,
                                                 sizeof(Elf64_Phdr));
    if (elf->phdrs == NULL)
      return -1;

    if (elf->phoff + (uint64_t)elf->phnum * elf->phentsize > bin->size) {
      fprintf(stderr, "Program headers table size exceeds file size\n");
      return -1;
    }

    for (size_t i = 0; i < elf->phnum; i++) {
      size_t offset = elf->phoff + i * elf->phentsize;
      if (offset + elf->phentsize > bin->size) {
        fprintf(stderr,
                "program header %zu is out of bounds (offset: %zu, size: %hu, "
                "buf_size: %zu)\n",
                i, offset, elf->phentsize, bin->size);
        return -1;
      }

      if (parse_elf_phdr(&elf->phdrs[i], bin->data + offset, bin->endianness,
                         bin->bitness) == -1)
        return -1;
    }
  }

  // Allocate array of section headers
  if (elf->shnum > 0) {
    elf->shdrs = (Elf64_Shdr *)arena_alloc_array(bin->arena, elf->shnum,
                                                 sizeof(Elf64_Shdr));
    if (elf->shdrs == NULL)
      return -1;

    if (elf->shoff + (uint64_t)elf->shnum * elf->shentsize > bin->size) {
      fprintf(stderr, "Section headers table size exceeds file size\n");
      return -1;
    }

    for (size_t i = 0; i < elf->shnum; i++) {
      size_t offset = elf->shoff + i * elf->shentsize;
      if (offset + elf->shentsize > bin->size) {
        fprintf(stderr,
                "Section header %zu is out of bounds (offset: %zu, size: %hu, "
                "buf_size: %zu)\n",
                i, offset, elf->shentsize, bin->size);
        return -1;
      }

      if (parse_elf_shdr(&elf->shdrs[i], bin->data + offset, bin->endianness,
                         bin->bitness) == -1)
        return -1;
    }
  }

  if (elf->shdrs && elf->shstrndx != SHN_UNDEF && elf->shstrndx < elf->shnum) {
    const Elf64_Shdr *shstrtab_hdr = &elf->shdrs[elf->shstrndx];
    elf->shstrtab_off = shstrtab_hdr->sh_offset;
    elf->shstrtab_size = shstrtab_hdr->sh_size;

    // Validate string table bounds
    if (elf->shstrtab_off + elf->shstrtab_size > bin->size) {
      fprintf(stderr, "String table section is out of bounds\n");
      return -1;
    }

    elf->shstrtab = (char *)arena_alloc(bin->arena, elf->shstrtab_size);
    if (elf->shstrtab == NULL)
      return -1;

    memcpy(elf->shstrtab, bin->data + elf->shstrtab_off, elf->shstrtab_size);
  }

  return EXIT_SUCCESS;
}
