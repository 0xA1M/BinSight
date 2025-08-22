#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "core/binary.h"
#include "core/error.h"
#include "elf_utils.h"

BError parse_elf(BinaryFile *bin, ELFInfo *elf);

#endif // ELF_PARSER_H
