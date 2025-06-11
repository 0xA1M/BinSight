#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "elf_utils.h"

int parse_elf32(const unsigned char *, ELFInfo *);
int parse_elf64(const unsigned char *, ELFInfo *);

#endif // ELF_PARSER_H
