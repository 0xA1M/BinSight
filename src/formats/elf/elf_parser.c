#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "formats/elf/elf_parser.h"
#include "formats/elf/elf_utils.h"

static Elf64_Ehdr *parse_elf_hdr(const uint8_t *buffer,
                                 const BinaryBitness bitness) {
  if (buffer == NULL || bitness == BITNESS_UNKNOWN)
    return NULL;

  Elf64_Ehdr *header = calloc(1, sizeof(Elf64_Ehdr));
  if (header == NULL) {
    fprintf(stderr, "Failed to allocate memory to store ELF header: %s\n",
            strerror(errno));
    return NULL;
  }

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

  return header;
}

static Elf64_Phdr *parse_elf_phdr(const uint8_t *buffer,
                                  const bool is_little_endian,
                                  const BinaryBitness bitness) {
  if (buffer == NULL || bitness == BITNESS_UNKNOWN)
    return NULL;

  Elf64_Phdr *p_header = calloc(1, sizeof(Elf64_Phdr));
  if (p_header == NULL) {
    fprintf(stderr,
            "Failed to allocate memory to store ELF program header: %s\n",
            strerror(errno));
    return NULL;
  }

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

  return p_header;
}

static Elf64_Shdr *parse_elf_shdr(const uint8_t *buffer,
                                  const bool is_little_endian,
                                  const BinaryBitness bitness) {
  if (buffer == NULL || bitness == BITNESS_UNKNOWN)
    return NULL;

  Elf64_Shdr *s_header = calloc(1, sizeof(Elf64_Shdr));
  if (s_header == NULL) {
    fprintf(stderr,
            "Failed to allocate memory to store ELF section header: %s\n",
            strerror(errno));
    return NULL;
  }

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

  return s_header;
}

static char *parse_elf_shstrtab(const uint8_t *buffer, size_t buf_size,
                                const Elf64_Shdr *shdrs,
                                const uint16_t shstrndx) {
  if (!buffer || !shdrs || shstrndx == SHN_UNDEF) {
    fprintf(stderr, "Invalid arguments to parse_elf_shstrtab\n");
    return NULL;
  }

  const Elf64_Shdr *shstrtab_hdr = &shdrs[shstrndx];

  // Validate string table bounds
  if (shstrtab_hdr->sh_offset + shstrtab_hdr->sh_size > buf_size) {
    fprintf(stderr, "String table section is out of bounds\n");
    return NULL;
  }

  char *shstrtab = calloc(1, shstrtab_hdr->sh_size);
  if (!shstrtab) {
    fprintf(stderr, "Failed to allocate memory for shstrtab\n");
    return NULL;
  }

  memcpy(shstrtab, buffer + shstrtab_hdr->sh_offset, shstrtab_hdr->sh_size);
  return shstrtab;
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

  Elf64_Ehdr *ehdr = parse_elf_hdr(bin->data, bin->bitness);
  if (ehdr == NULL)
    return -1;

  // Validate header values
  if (ehdr->e_shnum > SHN_LORESERVE) {
    fprintf(stderr, "Suspicious number of program/section headers\n");
    free(ehdr);
    return -1;
  }

  // Allocate array of program headers
  Elf64_Phdr *phdrs = NULL;
  if (ehdr->e_phnum > 0) {
    phdrs = (Elf64_Phdr *)calloc(ehdr->e_phnum, sizeof(Elf64_Phdr));
    if (phdrs == NULL) {
      fprintf(stderr, "Failed to allocate memory for program headers: %s\n",
              strerror(errno));
      free(ehdr);
      return -1;
    }

    for (size_t i = 0; i < ehdr->e_phnum; i++) {
      size_t offset = ehdr->e_phoff + i * ehdr->e_phentsize;
      if (offset + ehdr->e_phentsize > bin->size) {
        fprintf(stderr,
                "program header %zu is out of bounds (offset: %zu, size: %hu, "
                "buf_size: %zu)\n",
                i, offset, ehdr->e_phentsize, bin->size);
        free(ehdr);
        free(phdrs);
        return -1;
      }

      Elf64_Phdr *phdr =
          parse_elf_phdr(bin->data + offset, bin->endianness, bin->bitness);
      if (phdr == NULL) {
        free(ehdr);
        free(phdrs);
        return -1;
      }

      phdrs[i] = *phdr;
      free(phdr);
    }
  }

  // Allocate array of section headers
  Elf64_Shdr *shdrs = NULL;
  if (ehdr->e_shnum > 0) {
    shdrs = (Elf64_Shdr *)calloc(ehdr->e_shnum, sizeof(Elf64_Shdr));
    if (shdrs == NULL) {
      fprintf(stderr, "Failed to allocate memory for section headers: %s\n",
              strerror(errno));
      free(ehdr);
      free(phdrs);
      return -1;
    }

    for (size_t i = 0; i < ehdr->e_shnum; i++) {
      size_t offset = ehdr->e_shoff + i * ehdr->e_shentsize;
      if (offset + ehdr->e_shentsize > bin->size) {
        fprintf(stderr,
                "Section header %zu is out of bounds (offset: %zu, size: %hu, "
                "buf_size: %zu)\n",
                i, offset, ehdr->e_shentsize, bin->size);
        free(ehdr);
        free(phdrs);
        free(shdrs);
        return -1;
      }

      Elf64_Shdr *shdr =
          parse_elf_shdr(bin->data + offset, bin->endianness, bin->bitness);
      if (shdr == NULL) {
        free(ehdr);
        free(phdrs);
        free(shdrs);
        return -1;
      }

      shdrs[i] = *shdr;
      free(shdr);
    }
  }

  char *shstrtab = NULL;
  if (shdrs && ehdr->e_shstrndx != SHN_UNDEF &&
      ehdr->e_shstrndx < ehdr->e_shnum) {

    shstrtab =
        parse_elf_shstrtab(bin->data, bin->size, shdrs, ehdr->e_shstrndx);
    if (shstrtab == NULL) {
      free(ehdr);
      free(phdrs);
      free(shdrs);
      return -1;
    }
  }

  elf->ehdr = ehdr;
  elf->phdrs = phdrs;
  elf->phnum = ehdr->e_phnum;
  elf->shdrs = shdrs;
  elf->shnum = ehdr->e_shnum;
  elf->shstrtab = shstrtab;

  return 0;
}
