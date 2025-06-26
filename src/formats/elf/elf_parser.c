#include <elf.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_utils.h"
#include "utils.h"

static Elf32_Ehdr *parse_elf32_hdr(const unsigned char *buffer) {
  Elf32_Ehdr *header = calloc(1, sizeof(Elf32_Ehdr));
  if (header == NULL) {
    fprintf(stderr, "Failed to allocate memory to store ELF header: %s\n",
            strerror(errno));
    return NULL;
  }

  // Copy the magic bytes (EI_NIDENT = 16)
  memcpy(header->e_ident, buffer, EI_NIDENT);

  int is_little_endian = (header->e_ident[EI_DATA] == ELFDATA2LSB);
  size_t offset = EI_NIDENT;

  header->e_type = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_machine = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_version = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  header->e_entry = read_dword(buffer, offset, is_little_endian); // 32-bit
  offset += DWORD;

  header->e_phoff = read_dword(buffer, offset, is_little_endian); // 32-bit
  offset += DWORD;

  header->e_shoff = read_dword(buffer, offset, is_little_endian); // 32-bit
  offset += DWORD;

  header->e_flags = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  header->e_ehsize = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_phentsize = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_phnum = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_shentsize = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_shnum = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_shstrndx = read_word(buffer, offset, is_little_endian);

  return header;
}

static Elf64_Ehdr *parse_elf64_hdr(const unsigned char *buffer) {
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

  header->e_type = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_machine = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_version = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  header->e_entry = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  header->e_phoff = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  header->e_shoff = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  header->e_flags = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  header->e_ehsize = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_phentsize = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_phnum = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_shentsize = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_shnum = read_word(buffer, offset, is_little_endian);
  offset += WORD;

  header->e_shstrndx = read_word(buffer, offset, is_little_endian);

  return header;
}

static Elf32_Phdr *parse_elf32_phdr(const unsigned char *buffer,
                                    const bool is_little_endian) {
  Elf32_Phdr *p_header = calloc(1, sizeof(Elf32_Phdr));
  if (p_header == NULL) {
    fprintf(stderr, "Failed to allocate memory to store ELF header: %s\n",
            strerror(errno));
    return NULL;
  }

  size_t offset = 0;
  p_header->p_type = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_offset = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_vaddr = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_paddr = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_filesz = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_memsz = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_flags = read_dword(buffer, offset, is_little_endian);

  offset += DWORD;
  p_header->p_align = read_dword(buffer, offset, is_little_endian);

  return p_header;
}

static Elf64_Phdr *parse_elf64_phdr(const unsigned char *buffer,
                                    const bool is_little_endian) {
  Elf64_Phdr *p_header = calloc(1, sizeof(Elf64_Phdr));
  if (p_header == NULL) {
    fprintf(stderr, "Failed to allocate memory to store ELF header: %s\n",
            strerror(errno));
    return NULL;
  }

  size_t offset = 0;

  p_header->p_type = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  p_header->p_flags = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  p_header->p_offset = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  p_header->p_vaddr = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  p_header->p_paddr = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  p_header->p_filesz = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  p_header->p_memsz = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  p_header->p_align = read_qword(buffer, offset, is_little_endian);

  return p_header;
}

static Elf32_Shdr *parse_elf32_shdr(const unsigned char *buffer,
                                    const bool is_little_endian) {
  Elf32_Shdr *s_header = calloc(1, sizeof(Elf32_Shdr));
  if (s_header == NULL) {
    fprintf(stderr,
            "Failed to allocate memory to store ELF section header: %s\n",
            strerror(errno));
    return NULL;
  }

  size_t offset = 0;

  s_header->sh_name = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_type = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_flags = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_addr = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_offset = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_size = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_link = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_info = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_addralign = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_entsize = read_dword(buffer, offset, is_little_endian);

  return s_header;
}

static Elf64_Shdr *parse_elf64_shdr(const unsigned char *buffer,
                                    const bool is_little_endian) {
  Elf64_Shdr *s_header = calloc(1, sizeof(Elf64_Shdr));
  if (s_header == NULL) {
    fprintf(stderr,
            "Failed to allocate memory to store ELF section header: %s\n",
            strerror(errno));
    return NULL;
  }

  size_t offset = 0;

  s_header->sh_name = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_type = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_flags = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  s_header->sh_addr = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  s_header->sh_offset = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  s_header->sh_size = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  s_header->sh_link = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_info = read_dword(buffer, offset, is_little_endian);
  offset += DWORD;

  s_header->sh_addralign = read_qword(buffer, offset, is_little_endian);
  offset += QWORD;

  s_header->sh_entsize = read_qword(buffer, offset, is_little_endian);

  return s_header;
}

static char *parse_elf32_shstrtab(const unsigned char *buffer,
                                  const Elf32_Shdr *shdrs,
                                  const uint16_t shstrndx) {
  if (!buffer || !shdrs || shstrndx == SHN_UNDEF) {
    fprintf(stderr, "Invalid arguments to parse_shstrtab_elf64\n");
    return NULL;
  }

  Elf32_Shdr shstrtab_hdr = shdrs[shstrndx];

  char *shstrtab = calloc(1, shstrtab_hdr.sh_size);
  if (!shstrtab) {
    fprintf(stderr, "Failed to allocate memory for shstrtab\n");
    return NULL;
  }

  memcpy(shstrtab, buffer + shstrtab_hdr.sh_offset, shstrtab_hdr.sh_size);
  return shstrtab;
}

static char *parse_elf64_shstrtab(const unsigned char *buffer,
                                  const Elf64_Shdr *shdrs,
                                  const uint16_t shstrndx) {
  if (!buffer || !shdrs || shstrndx == SHN_UNDEF) {
    fprintf(stderr, "Invalid arguments to parse_shstrtab_elf64\n");
    return NULL;
  }

  Elf64_Shdr shstrtab_hdr = shdrs[shstrndx];

  char *shstrtab = calloc(1, shstrtab_hdr.sh_size);
  if (!shstrtab) {
    fprintf(stderr, "Failed to allocate memory for shstrtab\n");
    return NULL;
  }

  memcpy(shstrtab, buffer + shstrtab_hdr.sh_offset, shstrtab_hdr.sh_size);
  return shstrtab;
}

int parse_elf32(const unsigned char *buffer, ELFInfo *elf) {
  Elf32_Ehdr *ehdr = parse_elf32_hdr(buffer);
  if (!ehdr)
    return -1;

  bool is_little_endian = (ehdr->e_ident[EI_DATA] == ELFDATA2LSB);

  // Allocate array of program headers
  Elf32_Phdr *phdrs = calloc(ehdr->e_phnum, sizeof(Elf32_Phdr));
  if (!phdrs) {
    perror("calloc");
    free(ehdr);
    return -1;
  }

  for (int i = 0; i < ehdr->e_phnum; ++i) {
    size_t offset = ehdr->e_phoff + i * ehdr->e_phentsize;

    Elf32_Phdr *phdr = parse_elf32_phdr(buffer + offset, is_little_endian);
    if (phdr == NULL) {
      free(ehdr);
      free(phdrs);
      return -1;
    }

    phdrs[i] = *phdr;
    free(phdr); // Copy content then free temp
  }

  // Allocate array of section headers
  Elf32_Shdr *shdrs = calloc(ehdr->e_shnum, sizeof(Elf32_Shdr));
  if (shdrs == NULL) {
    perror("calloc");
    free(ehdr);
    free(phdrs);
    return -1;
  }

  for (size_t i = 0; i < ehdr->e_shnum; i++) {
    size_t offset = ehdr->e_shoff + i * ehdr->e_shentsize;

    Elf32_Shdr *shdr = parse_elf32_shdr(buffer + offset, is_little_endian);
    if (shdr == NULL) {
      free(ehdr);
      free(phdrs);
      free(shdrs);
      return -1;
    }

    shdrs[i] = *shdr;
    free(shdr); // Copy content then free temp
  }

  char *shstrtab = parse_elf32_shstrtab(buffer, shdrs, ehdr->e_shstrndx);
  if (shstrtab == NULL) {
    free(ehdr);
    free(phdrs);
    free(shdrs);
    return -1;
  }

  print_elf_ehdr(ehdr);
  print_elf_phdrs(phdrs, ELFCLASS32, ehdr->e_phnum);
  print_elf_shdrs(shdrs, ELFCLASS32, ehdr->e_shnum, shstrtab);

  elf->ehdr = ehdr;
  elf->phdrs = phdrs;
  elf->shdrs = shdrs;
  elf->shstrtab = shstrtab;

  return 0;
}

int parse_elf64(const unsigned char *buffer, ELFInfo *elf) {
  Elf64_Ehdr *ehdr = parse_elf64_hdr(buffer);
  if (ehdr == NULL)
    return -1;

  bool is_little_endian = (ehdr->e_ident[EI_DATA] == ELFDATA2LSB);

  // Allocate array of program headers
  Elf64_Phdr *phdrs = calloc(ehdr->e_phnum, sizeof(Elf64_Phdr));
  if (phdrs == NULL) {
    perror("calloc");
    free(ehdr);
    return -1;
  }

  for (size_t i = 0; i < ehdr->e_phnum; i++) {
    size_t offset = ehdr->e_phoff + i * ehdr->e_phentsize;

    Elf64_Phdr *phdr = parse_elf64_phdr(buffer + offset, is_little_endian);
    if (phdr == NULL) {
      free(ehdr);
      free(phdrs);
      return -1;
    }

    phdrs[i] = *phdr;
    free(phdr); // Copy content then free temp
  }

  // Allocate array of section headers
  Elf64_Shdr *shdrs = calloc(ehdr->e_shnum, sizeof(Elf64_Shdr));
  if (shdrs == NULL) {
    perror("calloc");
    free(ehdr);
    free(phdrs);
    return -1;
  }

  for (size_t i = 0; i < ehdr->e_shnum; i++) {
    size_t offset = ehdr->e_shoff + i * ehdr->e_shentsize;

    Elf64_Shdr *shdr = parse_elf64_shdr(buffer + offset, is_little_endian);
    if (shdr == NULL) {
      free(ehdr);
      free(phdrs);
      free(shdrs);
      return -1;
    }

    shdrs[i] = *shdr;
    free(shdr); // Copy content then free temp
  }

  char *shstrtab = parse_elf64_shstrtab(buffer, shdrs, ehdr->e_shstrndx);
  if (shstrtab == NULL) {
    free(ehdr);
    free(phdrs);
    free(shdrs);
    return -1;
  }

  print_elf_ehdr(ehdr);
  print_elf_phdrs(phdrs, ELFCLASS64, ehdr->e_phnum);
  print_elf_shdrs(shdrs, ELFCLASS64, ehdr->e_shnum, shstrtab);

  elf->ehdr = ehdr;
  elf->phdrs = phdrs;
  elf->shdrs = shdrs;
  elf->shstrtab = shstrtab;

  return 0;
}
