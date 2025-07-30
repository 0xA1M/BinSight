#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "core/binary.h"
#include "core/utils.h"
#include "elf_utils.h"

// Field reading macros for different bitness
#define READ_FIELD_32_64(header, field, buffer, offset, is_le, bitness)        \
  do {                                                                         \
    if ((bitness) == BITNESS_32) {                                             \
      (header)->field = read_dword(buffer, offset, is_le);                     \
      offset += DWORD;                                                         \
    } else {                                                                   \
      (header)->field = read_qword(buffer, offset, is_le);                     \
      offset += QWORD;                                                         \
    }                                                                          \
  } while (0)

#define READ_FIELD_QWORD(header, field, buffer, offset, is_le)                 \
  do {                                                                         \
    (header)->field = read_qword(buffer, offset, is_le);                       \
    offset += QWORD;                                                           \
  } while (0)

#define READ_FIELD_DWORD(header, field, buffer, offset, is_le)                 \
  do {                                                                         \
    (header)->field = read_dword(buffer, offset, is_le);                       \
    offset += DWORD;                                                           \
  } while (0)

#define READ_FIELD_WORD(header, field, buffer, offset, is_le)                  \
  do {                                                                         \
    (header)->field = read_word(buffer, offset, is_le);                        \
    offset += WORD;                                                            \
  } while (0)

int parse_elf(BinaryFile *bin, ELFInfo *elf);

#endif // ELF_PARSER_H
