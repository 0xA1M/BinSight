#include <stdio.h>

#include "core/binary.h"
#include "core/error.h"
#include "formats/elf/elf_print.h"

static const char *get_name_from_id(uint32_t id, const LT_Entry *table,
                                    uint64_t table_count) {
  for (size_t i = 0; i < table_count; i++)
    if (table[i].id == id)
      return table[i].name;

  return "Unknown";
}

/* Print ELF Header */
static const char *get_osabi_name(uint32_t osabi) {
  return get_name_from_id(osabi, osabi_names, ARR_COUNT(osabi_names));
}

static const char *get_type_name(uint32_t type) {
  return get_name_from_id(type, type_names, ARR_COUNT(type_names));
}

static const char *get_machine_name(uint32_t machine) {
  return get_name_from_id(machine, machine_names, ARR_COUNT(machine_names));
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

void print_elf_ehdr(Arena *arena, void *header) {
  ASSERT_RET(arena, header != NULL, ERR_ARG_NULL,
             "Failed to print ELF header, header is NULL");
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
         ehdr->e_phentsize);
  printf("  Number of program headers:         %u\n", ehdr->e_phnum);
  printf("  Size of section headers:           %u (bytes)\n",
         ehdr->e_shentsize);
  printf("  Number of section headers:         %u\n", ehdr->e_shnum);
  printf("  Section header string table index: %u\n", ehdr->e_shstrndx);
}

/* Print ELF Program Header Table */
static const char *phdr_type_to_str(uint32_t type) {
  if (type >= PT_LOOS && type <= PT_HIOS)
    return "OS-SPECIFIC";
  if (type >= PT_LOPROC && type <= PT_HIPROC)
    return "PROC-SPECIFIC";
  return get_name_from_id(type, phdr_type_names, ARR_COUNT(phdr_type_names));
}

void print_elf_phdr(Arena *arena, const void *phdrs, const uint16_t index) {
  ASSERT_RET(arena, phdrs != NULL, ERR_ARG_NULL,
             "Cannot print program header: missing data");

  printf("\nProgram Header: \n");
  printf("  %-15s %-18s %-18s %-18s %-18s %-18s %-6s %-10s\n", "Type", "Offset",
         "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");

  const Elf64_Phdr *ph = &((Elf64_Phdr *)phdrs)[index];
  printf("  %-15s 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx %c%c%c    "
         "0x%lx\n",
         phdr_type_to_str(ph->p_type), ph->p_offset, ph->p_vaddr, ph->p_paddr,
         ph->p_filesz, ph->p_memsz, (ph->p_flags & PF_R) ? 'R' : '-',
         (ph->p_flags & PF_W) ? 'W' : '-', (ph->p_flags & PF_X) ? 'X' : '-',
         ph->p_align);
}

void print_elf_phdrs(Arena *arena, const void *phdrs, const uint16_t phnum) {
  ASSERT_RET(arena, phdrs != NULL, ERR_ARG_NULL,
             "Cannot print program headers: missing data");

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
static const char *shdr_type_to_str(uint32_t type) {
  if (type >= SHT_LOOS && type <= SHT_HIOS)
    return "OS-SPECIFIC";
  if (type >= SHT_LOPROC && type <= SHT_HIPROC)
    return "PROC-SPECIFIC";
  return get_name_from_id(type, shdr_type_names, ARR_COUNT(shdr_type_names));
}

void print_elf_shdr(Arena *arena, const void *shdrs, const uint16_t index,
                    const char *shstrtab, const uint64_t shstrtab_size) {
  ASSERT_RET(arena, shdrs != NULL, ERR_ARG_NULL,
             "Cannot print section headers: missing data");

  printf("\nSection Headers:\n");
  printf("  [Nr] %-18s %-15s %-18s %-10s %-10s %-10s %-6s %-10s %-6s %-6s\n",
         "Name", "Type", "Addr", "Offset", "Size", "EntSize", "Align", "Flags",
         "Link", "Info");

  const Elf64_Shdr *sh = &((Elf64_Shdr *)shdrs)[index];
  const char *name = "???";
  if (shstrtab && sh->sh_name < shstrtab_size)
    name = &shstrtab[sh->sh_name];

  printf("  [%2u] %-18s %-15s 0x%016lx 0x%08lx 0x%08lx 0x%08lx %-6lu 0x%08lx "
         "%-6u %-6u\n",
         index, name, shdr_type_to_str(sh->sh_type), sh->sh_addr, sh->sh_offset,
         sh->sh_size, sh->sh_entsize, sh->sh_addralign, sh->sh_flags,
         sh->sh_link, sh->sh_info);
}

void print_elf_shdrs(Arena *arena, const void *shdrs, const uint16_t shnum,
                     const char *shstrtab, const uint64_t shstrtab_size) {
  ASSERT_RET(arena, shdrs != NULL, ERR_ARG_NULL,
             "Cannot print section headers: missing data");

  printf("\nSection Headers:\n");
  printf("  [Nr] %-18s %-15s %-18s %-10s %-10s %-10s %-6s %-10s %-6s %-6s\n",
         "Name", "Type", "Addr", "Offset", "Size", "EntSize", "Align", "Flags",
         "Link", "Info");

  const Elf64_Shdr *sh_arr = (Elf64_Shdr *)shdrs;
  for (uint16_t i = 0; i < shnum; ++i) {
    const Elf64_Shdr *sh = &sh_arr[i];
    const char *name = "???";
    if (shstrtab && sh->sh_name < shstrtab_size)
      name = &shstrtab[sh->sh_name];

    printf("  [%2u] %-18s %-15s 0x%016lx 0x%08lx 0x%08lx 0x%08lx %-6lu 0x%08lx "
           "%-6u %-6u\n",
           i, name, shdr_type_to_str(sh->sh_type), sh->sh_addr, sh->sh_offset,
           sh->sh_size, sh->sh_entsize, sh->sh_addralign, sh->sh_flags,
           sh->sh_link, sh->sh_info);
  }
}

/* Print ELF Symbol Table */
static const char *get_sym_bind_name(uint8_t info) {
  return get_name_from_id(ELF64_ST_BIND(info), sym_bind_names,
                          ARR_COUNT(sym_bind_names));
}

static const char *get_sym_type_name(uint8_t info) {
  return get_name_from_id(ELF64_ST_TYPE(info), sym_type_names,
                          ARR_COUNT(sym_type_names));
}

static const char *get_sym_visibility_name(uint8_t other) {
  return get_name_from_id(ELF64_ST_VISIBILITY(other), sym_visibility_names,
                          ARR_COUNT(sym_visibility_names));
}

void print_elf_sym(Arena *arena, const void *syms_ptr, const uint64_t index,
                   const char *strtab, const uint64_t strtab_size) {
  ASSERT_RET(arena, syms_ptr != NULL, ERR_ARG_NULL,
             "Cannot print symbol: missing data");

  const Elf64_Sym *sym = &((Elf64_Sym *)syms_ptr)[index];
  const char *name = "???";
  if (strtab && sym->st_name < strtab_size) {
    name = &strtab[sym->st_name];
  }

  printf("%6lu: %016lx %6lu %-7s %-6s %-8s", index, sym->st_value, sym->st_size,
         get_sym_type_name(ELF64_ST_TYPE(sym->st_info)),
         get_sym_bind_name(ELF64_ST_BIND(sym->st_info)),
         get_sym_visibility_name(ELF64_ST_VISIBILITY(sym->st_other)));

  if (sym->st_shndx == SHN_UNDEF)
    printf("  UND ");
  else if (sym->st_shndx == SHN_ABS)
    printf("  ABS ");
  else if (sym->st_shndx == SHN_COMMON)
    printf("  COM ");
  else
    printf("%5u ", sym->st_shndx);

  printf("%s\n", name);
}

void print_elf_syms(Arena *arena, const void *syms_ptr,
                    const uint64_t sym_count, const char *strtab,
                    const uint64_t strtab_size, const char *table_name) {
  ASSERT_RET(arena, syms_ptr != NULL, ERR_ARG_NULL,
             "Cannot print symbols: missing data");

  printf("\nSymbol table '%s' contains %lu entries:\n", table_name, sym_count);
  printf("   Num: Value            Size   Type    Bind   Vis       Ndx Name\n");

  const Elf64_Sym *sym_arr = (Elf64_Sym *)syms_ptr;
  for (uint64_t i = 0; i < sym_count; ++i) {
    print_elf_sym(arena, sym_arr, i, strtab, strtab_size);
  }
}

/* Print ELF Dynamic Section */
static const char *get_dynamic_tag_name(uint64_t tag) {
  if (tag >= DT_LOOS && tag <= DT_HIOS)
    return "OS-SPECIFIC";
  if (tag >= DT_LOPROC && tag <= DT_HIPROC)
    return "PROC-SPECIFIC";

  return get_name_from_id(tag, dyn_tag_names, ARR_COUNT(dyn_tag_names));
}

void print_elf_dynamic(Arena *arena, const ELFInfo *elf) {
  ASSERT_RET(arena, elf != NULL, ERR_ARG_NULL,
             "Cannot print dynamic section: ELFInfo struct is NULL");
  ASSERT_RET(arena, elf->dynamic.entries != NULL, ERR_ARG_NULL,
             "Cannot print dynamic section: missing dynamic data");

  printf("\nDynamic section contains %lu entries:\n", elf->dynamic.count);
  printf("  Tag                Type        Value\n");

  for (size_t i = 0; i < elf->dynamic.count; ++i) {
    const Elf64_Dyn *dyn_ent = &elf->dynamic.entries[i];
    const char *tag_name = get_dynamic_tag_name(dyn_ent->d_tag);

    printf("  0x%016lx %-12s 0x%016lx", dyn_ent->d_tag, tag_name,
           dyn_ent->d_un.d_val);

    // Print interpretations for specific tags
    switch (dyn_ent->d_tag) {
    case DT_NEEDED:
      if (elf->dynsym.strtab.str &&
          dyn_ent->d_un.d_val < elf->dynsym.strtab.len) {
        printf("  (%s)", elf->dynsym.strtab.str + dyn_ent->d_un.d_val);
      }
      break;
    case DT_SONAME:
      if (elf->dynsym.strtab.str &&
          dyn_ent->d_un.d_val < elf->dynsym.strtab.len) {
        printf("  Library soname: [%s]",
               elf->dynsym.strtab.str + dyn_ent->d_un.d_val);
      }
      break;
    case DT_RPATH:
      if (elf->dynsym.strtab.str &&
          dyn_ent->d_un.d_val < elf->dynsym.strtab.len) {
        printf("  RPath: [%s]", elf->dynsym.strtab.str + dyn_ent->d_un.d_val);
      }
      break;
    case DT_RUNPATH:
      if (elf->dynsym.strtab.str &&
          dyn_ent->d_un.d_val < elf->dynsym.strtab.len) {
        printf("  Runpath: [%s]", elf->dynsym.strtab.str + dyn_ent->d_un.d_val);
      }
      break;
    default:
      break;
    }
    printf("\n");
  }
}

/* Print whole ELF (readelf-style) */
void print_elf(Arena *arena, ELFInfo *elf) {
  ASSERT_RET(arena, elf != NULL, ERR_ARG_NULL,
             "Cannot print ELF: ELFInfo struct is NULL");

  print_elf_ehdr(arena, elf->ehdr);
  print_elf_phdrs(arena, elf->phdrs.headers, elf->phdrs.count);
  print_elf_shdrs(arena, elf->shdrs.headers, elf->ehdr->e_shnum,
                  elf->shdrs.strtab.str, elf->shdrs.strtab.len);
  print_elf_syms(arena, elf->dynsym.symbols, elf->dynsym.count,
                 elf->dynsym.strtab.str, elf->dynsym.strtab.len, ".dynsym");
  print_elf_syms(arena, elf->symtab.symbols, elf->symtab.count,
                 elf->symtab.strtab.str, elf->symtab.strtab.len, ".symtab");
  print_elf_dynamic(arena, elf);
}
