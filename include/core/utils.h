#ifndef UTILS_H
#define UTILS_H

#include "binary.h"

#define BYTE 1
#define WORD 2
#define DWORD 4
#define QWORD 8

typedef struct {
  uint32_t id;
  const char *name;
} LT_Entry; // Lookup Table Entry

#define ARR_COUNT(x) (sizeof(x) / sizeof((x)[0]))
#define CSTR_LEN(x) ((sizeof(x) / sizeof((x)[0])) - 1)

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define IS_POWER_2(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

#define NOT_IMPLEMENTED() printf("Not Implemented!\n");

#define READ_FIELD_32_64(header, field, buffer, offset, is_le, bitness)        \
  do {                                                                         \
    if ((bitness) == BITNESS_32) {                                             \
      (header)->field = read_dword(buffer, offset, is_le);                     \
      (offset) += DWORD;                                                       \
    } else {                                                                   \
      (header)->field = read_qword(buffer, offset, is_le);                     \
      (offset) += QWORD;                                                       \
    }                                                                          \
  } while (0)

#define READ_FIELD_BYTE(header, field, buffer, offset)                         \
  do {                                                                         \
    (header)->field = read_byte(buffer, offset);                               \
    (offset) += BYTE;                                                          \
  } while (0)

#define READ_FIELD_WORD(header, field, buffer, offset, is_le)                  \
  do {                                                                         \
    (header)->field = read_word(buffer, offset, is_le);                        \
    (offset) += WORD;                                                          \
  } while (0)

#define READ_FIELD_DWORD(header, field, buffer, offset, is_le)                 \
  do {                                                                         \
    (header)->field = read_dword(buffer, offset, is_le);                       \
    (offset) += DWORD;                                                         \
  } while (0)

#define READ_FIELD_QWORD(header, field, buffer, offset, is_le)                 \
  do {                                                                         \
    (header)->field = read_qword(buffer, offset, is_le);                       \
    (offset) += QWORD;                                                         \
  } while (0)

BinaryFormat get_binary_format(const char *mime_str);
const char *lookup_binary_format(BinaryFormat fmt);
void print_section_hex_dump(const char *section_name, const uint8_t *buffer,
                            size_t size, const uintptr_t section_offset);
void print_buffer_hex_dump(const uint8_t *buffer, size_t size,
                           const uintptr_t start_address);

static inline uint8_t read_byte(const uint8_t *buf, size_t offset) {
  return *(buf + offset);
}

static inline uint16_t read_word(const uint8_t *buf, size_t offset,
                                 bool is_little_endian) {
  const uint8_t *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8);

  return (p[0] << 8) | p[1];
}

static inline uint32_t read_dword(const uint8_t *buf, size_t offset,
                                  bool is_little_endian) {
  const uint8_t *p = buf + offset;

  if (is_little_endian)
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);

  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static inline uint64_t read_qword(const uint8_t *buf, size_t offset,
                                  bool is_little_endian) {
  const uint8_t *p = buf + offset;

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

#endif // UTILS_H
