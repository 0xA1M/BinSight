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
static const char *get_osabi_name(unsigned char osabi) {
  switch (osabi) {
  case ELFOSABI_SYSV || ELFOSABI_NONE:
    return "UNIX - System V";
  case ELFOSABI_HPUX:
    return "UNIX - HP-UX";
  case ELFOSABI_NETBSD:
    return "UNIX - NetBSD";
  case ELFOSABI_GNU:
    return "UNIX - GNU";
  case ELFOSABI_SOLARIS:
    return "UNIX - Solaris";
  case ELFOSABI_AIX:
    return "UNIX - AIX";
  case ELFOSABI_IRIX:
    return "UNIX - IRIX";
  case ELFOSABI_FREEBSD:
    return "UNIX - FreeBSD";
  case ELFOSABI_TRU64:
    return "UNIX - TRU64";
  case ELFOSABI_MODESTO:
    return "Novell - Modesto";
  case ELFOSABI_OPENBSD:
    return "UNIX - OpenBSD";
  case ELFOSABI_ARM_AEABI:
    return "ARM EABI";
  case ELFOSABI_ARM:
    return "ARM";
  case ELFOSABI_STANDALONE:
    return "Standalone (embedded) application";
  default:
    return "Unknown";
  }
}

static const char *get_type_name(const uint32_t type, uint64_t entry) {
  switch (type) {
  case ET_NONE:
    return "NONE (No file type)";
  case ET_REL:
    return "REL (Relocatable file)";
  case ET_EXEC:
    return "EXEC (Executable file)";
  case ET_DYN:
    return entry ? "DYN (Position-Independent Executable file)"
                 : "DYN (Shared object file)";
  case ET_CORE:
    return "CORE (Core file)";
  case ET_NUM:
    return "NUM (Number of defined types)";
  default:
    if (type >= ET_LOOS && type <= ET_HIOS)
      return "OS-specific";
    if (type >= ET_LOPROC && type <= ET_HIPROC)
      return "Processor-specific";
    return "Unknown";
  }
}

static const char *get_machine_name(uint16_t machine) {
  switch (machine) {
  case EM_NONE:
    return "No machine";
  case EM_M32:
    return "AT&T WE 32100";
  case EM_SPARC:
    return "SUN SPARC";
  case EM_386:
    return "Intel 80386";
  case EM_68K:
    return "Motorola m68k family";
  case EM_88K:
    return "Motorola m88k family";
  case EM_IAMCU:
    return "Intel MCU";
  case EM_860:
    return "Intel 80860";
  case EM_MIPS:
    return "MIPS R3000 big-endian";
  case EM_S370:
    return "IBM System/370";
  case EM_MIPS_RS3_LE:
    return "MIPS R3000 little-endian";
  case EM_PARISC:
    return "HPPA";
  case EM_VPP500:
    return "Fujitsu VPP500";
  case EM_SPARC32PLUS:
    return "SPARC v8plus";
  case EM_960:
    return "Intel 80960";
  case EM_PPC:
    return "PowerPC";
  case EM_PPC64:
    return "PowerPC 64-bit";
  case EM_S390:
    return "IBM S390";
  case EM_SPU:
    return "IBM SPU/SPC";
  case EM_V800:
    return "NEC V800 series";
  case EM_FR20:
    return "Fujitsu FR20";
  case EM_RH32:
    return "TRW RH-32";
  case EM_RCE:
    return "Motorola RCE";
  case EM_ARM:
    return "ARM";
  case EM_FAKE_ALPHA:
    return "Digital Alpha";
  case EM_SH:
    return "Hitachi SH";
  case EM_SPARCV9:
    return "SPARC v9 64-bit";
  case EM_TRICORE:
    return "Siemens Tricore";
  case EM_ARC:
    return "Argonaut RISC Core";
  case EM_H8_300:
    return "Hitachi H8/300";
  case EM_H8_300H:
    return "Hitachi H8/300H";
  case EM_H8S:
    return "Hitachi H8S";
  case EM_H8_500:
    return "Hitachi H8/500";
  case EM_IA_64:
    return "Intel Itanium (IA-64)";
  case EM_MIPS_X:
    return "Stanford MIPS-X";
  case EM_COLDFIRE:
    return "Motorola Coldfire";
  case EM_68HC12:
    return "Motorola M68HC12";
  case EM_MMA:
    return "Fujitsu MMA";
  case EM_PCP:
    return "Siemens PCP";
  case EM_NCPU:
    return "Sony nCPU";
  case EM_NDR1:
    return "Denso NDR1";
  case EM_STARCORE:
    return "Motorola Star*Core";
  case EM_ME16:
    return "Toyota ME16";
  case EM_ST100:
    return "STMicroelectronics ST100";
  case EM_TINYJ:
    return "Advanced Logic TinyJ";
  case EM_X86_64:
    return "Advanced Micro Devices X86-64";
  case EM_PDSP:
    return "Sony DSP";
  case EM_PDP10:
    return "Digital PDP-10";
  case EM_PDP11:
    return "Digital PDP-11";
  case EM_FX66:
    return "Siemens FX66";
  case EM_ST9PLUS:
    return "STMicroelectronics ST9+";
  case EM_ST7:
    return "STMicroelectronics ST7";
  case EM_68HC16:
    return "Motorola MC68HC16";
  case EM_68HC11:
    return "Motorola MC68HC11";
  case EM_68HC08:
    return "Motorola MC68HC08";
  case EM_68HC05:
    return "Motorola MC68HC05";
  case EM_SVX:
    return "Silicon Graphics SVx";
  case EM_ST19:
    return "STMicroelectronics ST19";
  case EM_VAX:
    return "Digital VAX";
  case EM_CRIS:
    return "Axis CRIS";
  case EM_JAVELIN:
    return "Infineon Javelin";
  case EM_FIREPATH:
    return "Element 14 FirePath";
  case EM_ZSP:
    return "LSI Logic ZSP";
  case EM_MMIX:
    return "Donald Knuth's MMIX";
  case EM_HUANY:
    return "Harvard HUANY";
  case EM_PRISM:
    return "SiTera Prism";
  case EM_AVR:
    return "Atmel AVR";
  case EM_FR30:
    return "Fujitsu FR30";
  case EM_D10V:
    return "Mitsubishi D10V";
  case EM_D30V:
    return "Mitsubishi D30V";
  case EM_V850:
    return "NEC v850";
  case EM_M32R:
    return "Mitsubishi M32R";
  case EM_MN10300:
    return "Matsushita MN10300";
  case EM_MN10200:
    return "Matsushita MN10200";
  case EM_PJ:
    return "picoJava";
  case EM_OPENRISC:
    return "OpenRISC";
  case EM_ARC_COMPACT:
    return "ARC Compact";
  case EM_XTENSA:
    return "Tensilica Xtensa";
  case EM_VIDEOCORE:
    return "Alphamosaic VideoCore";
  case EM_TMM_GPP:
    return "Thompson Multimedia GPP";
  case EM_NS32K:
    return "National Semi. 32000";
  case EM_TPC:
    return "Tenor Network TPC";
  case EM_SNP1K:
    return "Trebia SNP 1000";
  case EM_ST200:
    return "STMicroelectronics ST200";
  case EM_IP2K:
    return "Ubicom IP2xxx";
  case EM_MAX:
    return "MAX processor";
  case EM_CR:
    return "National Semi. CompactRISC";
  case EM_F2MC16:
    return "Fujitsu F2MC16";
  case EM_MSP430:
    return "Texas Instruments MSP430";
  case EM_BLACKFIN:
    return "Analog Devices Blackfin";
  case EM_SE_C33:
    return "Seiko Epson S1C33";
  case EM_SEP:
    return "Sharp embedded";
  case EM_ARCA:
    return "Arca RISC";
  case EM_UNICORE:
    return "PKU-Unity";
  case EM_EXCESS:
    return "eXcess";
  case EM_DXP:
    return "Icera Semi. DXP";
  case EM_ALTERA_NIOS2:
    return "Altera Nios II";
  case EM_CRX:
    return "National Semi. CRX";
  case EM_XGATE:
    return "Motorola XGATE";
  case EM_C166:
    return "Infineon C16x/XC16x";
  case EM_M16C:
    return "Renesas M16C";
  case EM_DSPIC30F:
    return "Microchip dsPIC30F";
  case EM_CE:
    return "Freescale Communication Engine";
  case EM_M32C:
    return "Renesas M32C";
  case EM_TSK3000:
    return "Altium TSK3000";
  case EM_RS08:
    return "Freescale RS08";
  case EM_SHARC:
    return "Analog Devices SHARC";
  case EM_ECOG2:
    return "Cyan Technology eCOG2";
  case EM_SCORE7:
    return "Sunplus S+core7";
  case EM_DSP24:
    return "NJR 24-bit DSP";
  case EM_VIDEOCORE3:
    return "Broadcom VideoCore III";
  case EM_LATTICEMICO32:
    return "LatticeMico32";
  case EM_SE_C17:
    return "Seiko Epson C17";
  case EM_TI_C6000:
    return "TI TMS320C6000 DSP";
  case EM_TI_C2000:
    return "TI TMS320C2000 DSP";
  case EM_TI_C5500:
    return "TI TMS320C55x DSP";
  case EM_TI_ARP32:
    return "TI App. Specific RISC";
  case EM_TI_PRU:
    return "TI PRU";
  case EM_MMDSP_PLUS:
    return "STMicroelectronics 64bit VLIW DSP";
  case EM_CYPRESS_M8C:
    return "Cypress M8C";
  case EM_R32C:
    return "Renesas R32C";
  case EM_TRIMEDIA:
    return "NXP TriMedia";
  case EM_QDSP6:
    return "QUALCOMM DSP6";
  case EM_8051:
    return "Intel 8051";
  case EM_STXP7X:
    return "STMicroelectronics STxP7x";
  case EM_NDS32:
    return "Andes Tech. NDS32";
  case EM_ECOG1X:
    return "Cyan Technology eCOG1X";
  case EM_MAXQ30:
    return "Dallas Semi. MAXQ30";
  case EM_XIMO16:
    return "NJR 16-bit DSP";
  case EM_MANIK:
    return "M2000 Reconfigurable RISC";
  case EM_CRAYNV2:
    return "Cray NV2";
  case EM_RX:
    return "Renesas RX";
  case EM_METAG:
    return "Imagination Tech. META";
  case EM_MCST_ELBRUS:
    return "MCST Elbrus";
  case EM_ECOG16:
    return "Cyan Technology eCOG16";
  case EM_CR16:
    return "National Semi. CR16";
  case EM_ETPU:
    return "Freescale ETPU";
  case EM_SLE9X:
    return "Infineon SLE9X";
  case EM_L10M:
    return "Intel L10M";
  case EM_K10M:
    return "Intel K10M";
  case EM_AARCH64:
    return "AArch64";
  case EM_AVR32:
    return "Atmel AVR32";
  case EM_STM8:
    return "STMicroelectronics STM8";
  case EM_TILE64:
    return "Tilera TILE64";
  case EM_TILEPRO:
    return "Tilera TILEPro";
  case EM_MICROBLAZE:
    return "Xilinx MicroBlaze";
  case EM_CUDA:
    return "NVIDIA CUDA";
  case EM_TILEGX:
    return "Tilera TILE-Gx";
  case EM_CLOUDSHIELD:
    return "CloudShield";
  case EM_COREA_1ST:
    return "KIPO-KAIST Core-A 1st gen";
  case EM_COREA_2ND:
    return "KIPO-KAIST Core-A 2nd gen";
  case EM_ARCV2:
    return "Synopsys ARCv2";
  case EM_OPEN8:
    return "Open8 RISC";
  case EM_RL78:
    return "Renesas RL78";
  case EM_VIDEOCORE5:
    return "Broadcom VideoCore V";
  case EM_78KOR:
    return "Renesas 78KOR";
  case EM_56800EX:
    return "Freescale 56800EX DSC";
  case EM_BA1:
    return "Beyond BA1";
  case EM_BA2:
    return "Beyond BA2";
  case EM_XCORE:
    return "XMOS xCORE";
  case EM_MCHP_PIC:
    return "Microchip PIC";
  case EM_INTELGT:
    return "Intel Graphics Technology";
  case EM_KM32:
    return "KM211 KM32";
  case EM_KMX32:
    return "KM211 KMX32";
  case EM_EMX16:
    return "KM211 EMX16";
  case EM_EMX8:
    return "KM211 EMX8";
  case EM_KVARC:
    return "KM211 KVARC";
  case EM_CDP:
    return "Paneve CDP";
  case EM_COGE:
    return "Cognitive Smart Memory";
  case EM_COOL:
    return "Bluechip CoolEngine";
  case EM_NORC:
    return "Nanoradio Optimized RISC";
  case EM_CSR_KALIMBA:
    return "CSR Kalimba";
  case EM_Z80:
    return "Zilog Z80";
  case EM_VISIUM:
    return "Controls and Data Services VISIUMcore";
  case EM_FT32:
    return "FTDI Chip FT32";
  case EM_MOXIE:
    return "Moxie processor";
  case EM_AMDGPU:
    return "AMD GPU";
  case EM_RISCV:
    return "RISC-V";
  case EM_BPF:
    return "Linux BPF";
  case EM_CSKY:
    return "C-SKY";
  case EM_LOONGARCH:
    return "LoongArch";
  default:
    return "Unknown";
  }
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

static void print_elf32_header(Elf32_Ehdr *ehdr) {
  print_e_ident(ehdr->e_ident);

  printf("  Type:                              %s\n",
         get_type_name(ehdr->e_type, ehdr->e_entry));
  printf("  Machine:                           %s\n",
         get_machine_name(ehdr->e_machine));
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

  printf("  Type:                              %s\n",
         get_type_name(ehdr->e_type, ehdr->e_entry));
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
