#include <stdio.h>

#include "core/utils.h"
#include "formats/elf/elf_print.h"
#include "formats/elf/elf_utils.h"

/* Print ELF Header */
const char *get_osabi_name(uint8_t osabi) {
  for (size_t i = 0; i < ARR_COUNT(osabi_names); i++) {
    if (osabi_names[i].id == osabi)
      return osabi_names[i].name;
  }
  return "Unknown";
}

static const char *get_type_name(uint16_t type) {
  for (size_t i = 0; i < ARR_COUNT(type_names); i++) {
    if (type_names[i].id == type)
      return type_names[i].name;
  }
  return "Unknown";
}

static const char *get_machine_name(uint16_t machine) {
  for (size_t i = 0; i < ARR_COUNT(machine_names); i++) {
    if (machine_names[i].id == machine)
      return machine_names[i].name;
  }
  return "Unknown";
}

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

  printf("  Version:                           %d", e_ident[EI_VERSION]);
  if (e_ident[EI_VERSION] == 1)
    printf(" (current)");
  printf("\n");

  printf("  OS/ABI:                            %s\n",
         get_osabi_name(e_ident[EI_OSABI]));
  printf("  ABI Version:                       %d\n", e_ident[EI_ABIVERSION]);
}

void print_elf_ehdr(void *header) {
  if (header == NULL) {
    fprintf(stderr, "Failed to print elf header, header empty!\n");
    return;
  }
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)header;

  print_e_ident(ehdr->e_ident);

  printf("  Type:                              %s\n",
         get_type_name(ehdr->e_type));
  printf("  Machine:                           %s\n",
         get_machine_name(ehdr->e_machine));
  printf("  Version:                           0x%x\n", ehdr->e_version);
  printf("  Entry point address:               0x%lx\n", ehdr->e_entry);
  printf("  Start of program headers:          %lu (bytes into file)\n",
         ehdr->e_phoff);
  printf("  Start of section headers:          %lu (bytes into file)\n",
         ehdr->e_shoff);
  printf("  Flags:                             0x%x\n", ehdr->e_flags);
  printf("  Size of this header:               %u (bytes)\n", ehdr->e_ehsize);
  printf("  Size of program headers:           %u (bytes)\n",
         ehdr->e_phentsize); // Fixed: removed multiplication
  printf("  Number of program headers:         %u\n", ehdr->e_phnum);
  printf("  Size of section headers:           %u (bytes)\n",
         ehdr->e_shentsize); // Fixed: removed multiplication
  printf("  Number of section headers:         %u\n", ehdr->e_shnum);
  printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

/* Print ELF Program Header Table */
const char *phdr_type_to_str(uint32_t type) {
  for (size_t i = 0; i < ARR_COUNT(phdr_type_names); i++) {
    if (phdr_type_names[i].id == type)
      return phdr_type_names[i].name;
  }
  if (type >= PT_LOOS && type <= PT_HIOS)
    return "OS-SPECIFIC";
  if (type >= PT_LOPROC && type <= PT_HIPROC)
    return "PROC-SPECIFIC";
  return "UNKNOWN";
}

void print_elf_phdrs(const void *phdrs, const uint16_t phnum) {
  if (!phdrs) {
    fprintf(stderr, "Cannot print program headers: missing data.\n");
    return;
  }

  printf("\nProgram Headers: \n");
  printf("  %-15s %-18s %-18s %-18s %-18s %-18s %-6s %-10s\n", "Type", "Offset",
         "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");

  const Elf64_Phdr *ph_arr = (Elf64_Phdr *)phdrs;
  for (size_t i = 0; i < phnum; ++i) {
    const Elf64_Phdr *ph = &ph_arr[i];

    printf("  %-15s 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx %c%c%c    "
           "0x%lx\n",
           phdr_type_to_str(ph->p_type), ph->p_offset, ph->p_vaddr, ph->p_paddr,
           ph->p_filesz, ph->p_memsz, (ph->p_flags & PF_R) ? 'R' : '-',
           (ph->p_flags & PF_W) ? 'W' : '-', (ph->p_flags & PF_X) ? 'X' : '-',
           ph->p_align);
  }
}

/* Print ELF Section Header Table */
const char *shdr_type_to_str(uint32_t type) {
  for (size_t i = 0; i < ARR_COUNT(shdr_type_names); i++) {
    if (shdr_type_names[i].id == type)
      return shdr_type_names[i].name;
  }
  if (type >= SHT_LOOS && type <= SHT_HIOS)
    return "OS-SPECIFIC";
  if (type >= SHT_LOPROC && type <= SHT_HIPROC)
    return "PROC-SPECIFIC";
  return "UNKNOWN";
}

void print_elf_shdrs(const void *shdrs, const uint16_t shnum,
                     const char *shstrtab) {
  if (!shdrs) {
    fprintf(stderr, "Cannot print section headers: missing data.\n");
    return;
  }

  printf("\nSection Headers:\n");
  printf("  [Nr] %-18s %-15s %-18s %-10s %-10s %-10s %-6s %-10s %-6s %-6s\n",
         "Name", "Type", "Addr", "Offset", "Size", "EntSize", "Align", "Flags",
         "Link", "Info");

  const Elf64_Shdr *sh_arr = (Elf64_Shdr *)shdrs;
  for (uint16_t i = 0; i < shnum; ++i) {
    const Elf64_Shdr *sh = &sh_arr[i];
    const char *name = shstrtab ? &shstrtab[sh->sh_name] : "???";

    printf("  [%2u] %-18s %-15s 0x%016lx 0x%08lx 0x%08lx 0x%08lx %-6lu 0x%08lx "
           "%-6u %-6u\n",
           i, name, shdr_type_to_str(sh->sh_type), sh->sh_addr, sh->sh_offset,
           sh->sh_size, sh->sh_entsize, sh->sh_addralign, sh->sh_flags,
           sh->sh_link, sh->sh_info);
  }
}

/* Print whole ELF */
void print_elf(void *elf_ptr) {
  const ELFInfo *elf = (ELFInfo *)elf_ptr;

  if (!elf) {
    fprintf(stderr, "Cannot print ELF: ELFInfo struct is NULL.\n");
    return;
  }

  print_elf_ehdr(elf->ehdr);
  print_elf_phdrs(elf->phdrs, elf->phnum);
  print_elf_shdrs(elf->shdrs, elf->shnum, elf->shstrtab);
}
