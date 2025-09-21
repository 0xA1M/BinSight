#ifndef UTILS_H
#define UTILS_H

#include "binary.h"

#define BYTE 1
#define WORD 2
#define DWORD 4
#define QWORD 8

typedef struct LT_Entry {
  uint32_t id;
  const char *name;
} LT_Entry; // Lookup Table Entry

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define IS_POWER_2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

#define ARR_COUNT(x) (sizeof(x) / sizeof((x)[0]))
#define CSTR_LEN(x) (sizeof(x) - 1)

#define STR "%.*s"
#define EMPTY_STR (String){.str = NULL, .len = 0}
#define IS_STR_EMPTY(s) ((s).str == NULL && (s).len == 0)
#define CONST_STR(s)                                                           \
  (String) { .str = (s), .len = CSTR_LEN(s) }

BinaryFormat get_binary_format(Arena *arena, String mime);
String lookup_binary_format(BinaryFormat fmt);

static inline uint8_t read_byte(const uint8_t *buf, size_t offset) {
  return *(buf + offset);
}

static inline uint16_t read_word(const uint8_t *buf, size_t offset,
                                 BinaryEndianness endianness) {
  const uint8_t *p = buf + offset;

  if (endianness == ENDIANNESS_LITTLE)
    return p[0] | (p[1] << 8);

  return (p[0] << 8) | p[1];
}

static inline uint32_t read_dword(const uint8_t *buf, size_t offset,
                                  BinaryEndianness endianness) {
  const uint8_t *p = buf + offset;

  if (endianness == ENDIANNESS_LITTLE)
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);

  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static inline uint64_t read_qword(const uint8_t *buf, size_t offset,
                                  BinaryEndianness endianness) {
  const uint8_t *p = buf + offset;

  if (endianness == ENDIANNESS_LITTLE)
    return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);

  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | ((uint64_t)p[7]);
}

#endif // UTILS_H
