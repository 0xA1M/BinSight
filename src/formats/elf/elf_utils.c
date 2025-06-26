#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_utils.h"

ELFInfo *init_elf(void) {
  ELFInfo *elf = calloc(1, sizeof(ELFInfo));
  if (elf == NULL) {
    fprintf(stderr, "Failed to allocate memory: %s\n", strerror(errno));
    return NULL;
  }

  elf->ehdr = NULL;
  elf->phdrs = NULL;
  elf->shdrs = NULL;
  elf->shstrtab = NULL;
  elf->strtab = NULL;
  elf->symtab = NULL;
  elf->rela = NULL;

  return elf;
}

void free_elf(ELFInfo *elf) {
  if (!elf)
    return;

  // Free header and tables
  free(elf->ehdr);
  free(elf->phdrs);
  free(elf->shdrs);

  // Section name string table
  free(elf->shstrtab);

  // General string table
  free(elf->strtab);

  // Free symbol table
  if (elf->symtab) {
    free(elf->symtab);
    elf->symtab = NULL;
  }

  // Free relocation entries
  if (elf->rela) {
    free(elf->rela);
    elf->rela = NULL;
  }

  free(elf);
}

uint8_t read_byte(const unsigned char *buf, size_t offset) {
  return *(buf + offset);
}

uint16_t read_word(const unsigned char *buf, size_t offset,
                   bool is_little_endian) {
  const unsigned char *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8);

  return (p[0] << 8) | p[1];
}

uint32_t read_dword(const unsigned char *buf, size_t offset,
                    bool is_little_endian) {
  const unsigned char *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);

  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

uint64_t read_qword(const unsigned char *buf, size_t offset,
                    bool is_little_endian) {
  const unsigned char *p = buf + offset;

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

/* Print ELF Header */

static void print_e_ident(unsigned char *e_ident) {
  printf("ELF Header:\n");
  printf("  Magic:   ");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%02x ", e_ident[i]);
  }
  printf("\n");
  printf("  Class:                             ");
  switch (e_ident[EI_CLASS]) {
  case ELFCLASS32:
    printf("ELF32\n");
    break;
  case ELFCLASS64:
    printf("ELF64\n");
    break;
  default:
    printf("Invalid\n");
    break;
  }
  printf("  Data:                              ");
  switch (e_ident[EI_DATA]) {
  case ELFDATA2LSB:
    printf("2's complement, little endian\n");
    break;
  case ELFDATA2MSB:
    printf("2's complement, big endian\n");
    break;
  default:
    printf("Invalid\n");
    break;
  }
  printf("  Version:                           %d\n", e_ident[EI_VERSION]);
}

static void print_elf32_header(Elf32_Ehdr *ehdr) {
  print_e_ident(ehdr->e_ident);
  printf("  Type:                              %u\n", ehdr->e_type);
  printf("  Machine:                           %u\n", ehdr->e_machine);
  printf("  Version:                           0x%x\n", ehdr->e_version);
  printf("  Entry point address:               0x%x\n", ehdr->e_entry);
  printf("  Start of program headers:          %u (bytes into file)\n",
         ehdr->e_phoff);
  printf("  Start of section headers:          %u (bytes into file)\n",
         ehdr->e_shoff);
  printf("  Flags:                             0x%x\n", ehdr->e_flags);
  printf("  Size of this header:               %u (bytes)\n", ehdr->e_ehsize);
  printf("  Size of program headers:           %u (bytes)\n",
         ehdr->e_phentsize);
  printf("  Number of program headers:         %u\n", ehdr->e_phnum);
  printf("  Size of section headers:           %u (bytes)\n",
         ehdr->e_shentsize);
  printf("  Number of section headers:         %u\n", ehdr->e_shnum);
  printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

static void print_elf64_header(Elf64_Ehdr *ehdr) {
  print_e_ident(ehdr->e_ident);
  printf("  Type:                              %u\n", ehdr->e_type);
  printf("  Machine:                           %u\n", ehdr->e_machine);
  printf("  Version:                           0x%x\n", ehdr->e_version);
  printf("  Entry point address:               0x%lx\n", ehdr->e_entry);
  printf("  Start of program headers:          %lu (bytes into file)\n",
         ehdr->e_phoff);
  printf("  Start of section headers:          %lu (bytes into file)\n",
         ehdr->e_shoff);
  printf("  Flags:                             0x%x\n", ehdr->e_flags);
  printf("  Size of this header:               %u (bytes)\n", ehdr->e_ehsize);
  printf("  Size of program headers:           %u (bytes)\n",
         ehdr->e_phentsize * ehdr->e_phnum);
  printf("  Number of program headers:         %u\n", ehdr->e_phnum);
  printf("  Size of section headers:           %u (bytes)\n",
         ehdr->e_shentsize * ehdr->e_shnum);
  printf("  Number of section headers:         %u\n", ehdr->e_shnum);
  printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

void print_elf_ehdr(void *header) {
  if (header == NULL) {
    fprintf(stderr, "Failed to print elf header, header empty!\n");
    return;
  }

  int bitness = ((unsigned char *)header)[EI_CLASS];
  if (bitness == ELFCLASS32) {
    print_elf32_header((Elf32_Ehdr *)header);
  } else if (bitness == ELFCLASS64) {
    print_elf64_header((Elf64_Ehdr *)header);
  } else {
    printf("Unknown ELF class: %d\n", bitness);
  }
}

/* Print ELF Program Header Table */
static const char *phdr_type_to_str(uint32_t type) {
  switch (type) {
  case PT_NULL:
    return "NULL";
  case PT_LOAD:
    return "LOAD";
  case PT_DYNAMIC:
    return "DYNAMIC";
  case PT_INTERP:
    return "INTERP";
  case PT_NOTE:
    return "NOTE";
  case PT_SHLIB:
    return "SHLIB";
  case PT_PHDR:
    return "PHDR";
  case PT_TLS:
    return "TLS";
  case PT_GNU_EH_FRAME:
    return "GNU_EH_FRAME";
  case PT_GNU_STACK:
    return "GNU_STACK";
  case PT_GNU_RELRO:
    return "GNU_RELRO";
  case PT_GNU_PROPERTY:
    return "GNU_PROPERTY";
  case PT_GNU_SFRAME:
    return "GNU_SFRAME";
  case PT_SUNWBSS:
    return "SUNWBSS";
  case PT_SUNWSTACK:
    return "SUNWSTACK";
  default:
    if (type >= PT_LOOS && type <= PT_HIOS)
      return "OS-SPECIFIC";
    else if (type >= PT_LOPROC && type <= PT_HIPROC)
      return "PROC-SPECIFIC";
    else
      return "UNKNOWN";
  }
}

static void print_elf32_program_headers(Elf32_Phdr *phdrs, uint16_t phnum) {
  printf("\nProgram Headers (32-bit):\n");
  printf("  %-15s %-10s %-10s %-10s %-10s %-10s %-6s %-10s\n", "Type", "Offset",
         "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");

  for (size_t i = 0; i < phnum; ++i) {
    Elf32_Phdr *ph = &phdrs[i];
    printf("  %-15s 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x %c%c%c    0x%x\n",
           phdr_type_to_str(ph->p_type), ph->p_offset, ph->p_vaddr, ph->p_paddr,
           ph->p_filesz, ph->p_memsz, (ph->p_flags & PF_R) ? 'R' : '-',
           (ph->p_flags & PF_W) ? 'W' : '-', (ph->p_flags & PF_X) ? 'X' : '-',
           ph->p_align);
  }
}

static void print_elf64_program_headers(Elf64_Phdr *phdrs, uint16_t phnum) {
  printf("\nProgram Headers (64-bit):\n");
  printf("  %-15s %-18s %-18s %-18s %-18s %-18s %-6s %-10s\n", "Type", "Offset",
         "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");

  for (size_t i = 0; i < phnum; ++i) {
    Elf64_Phdr *ph = &phdrs[i];
    printf("  %-15s 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx %c%c%c    "
           "0x%lx\n",
           phdr_type_to_str(ph->p_type), ph->p_offset, ph->p_vaddr, ph->p_paddr,
           ph->p_filesz, ph->p_memsz, (ph->p_flags & PF_R) ? 'R' : '-',
           (ph->p_flags & PF_W) ? 'W' : '-', (ph->p_flags & PF_X) ? 'X' : '-',
           ph->p_align);
  }
}

void print_elf_phdrs(const void *phdrs, int bitness, const uint16_t phnum) {
  if (!phdrs) {
    fprintf(stderr, "Cannot print program headers: missing data.\n");
    return;
  }

  if (bitness == ELFCLASS32) {
    print_elf32_program_headers((Elf32_Phdr *)phdrs, phnum);
  } else if (bitness == ELFCLASS64) {
    print_elf64_program_headers((Elf64_Phdr *)phdrs, phnum);
  } else {
    fprintf(stderr, "Unknown ELF class in program header printing.\n");
  }
}

/* Print ELF Section Header Table */
static const char *shdr_type_to_str(uint32_t type) {
  switch (type) {
  case SHT_NULL:
    return "NULL";
  case SHT_PROGBITS:
    return "PROGBITS";
  case SHT_SYMTAB:
    return "SYMTAB";
  case SHT_STRTAB:
    return "STRTAB";
  case SHT_RELA:
    return "RELA";
  case SHT_HASH:
    return "HASH";
  case SHT_DYNAMIC:
    return "DYNAMIC";
  case SHT_NOTE:
    return "NOTE";
  case SHT_NOBITS:
    return "NOBITS";
  case SHT_REL:
    return "REL";
  case SHT_SHLIB:
    return "SHLIB";
  case SHT_DYNSYM:
    return "DYNSYM";
  case SHT_INIT_ARRAY:
    return "INIT_ARRAY";
  case SHT_FINI_ARRAY:
    return "FINI_ARRAY";
  case SHT_PREINIT_ARRAY:
    return "PREINIT_ARRAY";
  case SHT_GROUP:
    return "GROUP";
  case SHT_SYMTAB_SHNDX:
    return "SYMTAB_SHNDX";
  case SHT_NUM:
    return "NUM";
  default:
    if (type >= SHT_LOOS && type <= SHT_HIOS)
      return "OS-SPECIFIC";
    else if (type >= SHT_LOPROC && type <= SHT_HIPROC)
      return "PROC-SPECIFIC";
    else
      return "UNKNOWN";
  }
}

static void print_elf32_section_headers(Elf32_Shdr *shdrs, uint16_t shnum,
                                        const char *shstrtab) {
  printf("\nSection Headers (32-bit):\n");
  printf("  [Nr] %-18s %-15s %-8s %-8s %-8s %-8s %-6s %-6s %-6s %-6s\n", "Name",
         "Type", "Addr", "Offset", "Size", "EntSize", "Align", "Flags", "Link",
         "Info");

  for (uint16_t i = 0; i < shnum; ++i) {
    Elf32_Shdr *sh = &shdrs[i];
    const char *name = shstrtab ? &shstrtab[sh->sh_name] : "???";

    printf(
        "  [%2u] %-18s %-15s 0x%06x 0x%06x 0x%06x 0x%06x %-6u 0x%x %-6u %-6u\n",
        i, name, shdr_type_to_str(sh->sh_type), sh->sh_addr, sh->sh_offset,
        sh->sh_size, sh->sh_entsize, sh->sh_addralign, sh->sh_flags,
        sh->sh_link, sh->sh_info);
  }
}

static void print_elf64_section_headers(Elf64_Shdr *shdrs, uint16_t shnum,
                                        const char *shstrtab) {
  printf("\nSection Headers (64-bit):\n");
  printf("  [Nr] %-18s %-15s %-18s %-10s %-10s %-10s %-6s %-6s %-6s %-6s\n",
         "Name", "Type", "Addr", "Offset", "Size", "EntSize", "Align", "Flags",
         "Link", "Info");

  for (uint16_t i = 0; i < shnum; ++i) {
    Elf64_Shdr *sh = &shdrs[i];
    const char *name = shstrtab ? &shstrtab[sh->sh_name] : "???";

    printf("  [%2u] %-18s %-15s 0x%016lx 0x%08lx 0x%08lx 0x%08lx %-6lu "
           "0x%lx "
           "%-6u %-6u\n",
           i, name, shdr_type_to_str(sh->sh_type), sh->sh_addr, sh->sh_offset,
           sh->sh_size, sh->sh_entsize, sh->sh_addralign, sh->sh_flags,
           sh->sh_link, sh->sh_info);
  }
}

void print_elf_shdrs(const void *shdrs, int bitness, const uint16_t shnum,
                     const char *shstrtab) {
  if (!shdrs) {
    fprintf(stderr, "Cannot print section headers: missing data.\n");
    return;
  }

  if (bitness == ELFCLASS32) {
    print_elf32_section_headers((Elf32_Shdr *)shdrs, shnum, shstrtab);
  } else if (bitness == ELFCLASS64) {
    print_elf64_section_headers((Elf64_Shdr *)shdrs, shnum, shstrtab);
  } else {
    fprintf(stderr, "Unknown ELF class in section header printing.\n");
  }
}
