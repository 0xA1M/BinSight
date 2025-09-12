#ifndef READER_H
#define READER_H

#include "binary.h"
#include "error.h"
#include "mem.h"

typedef struct Reader {
  const uint8_t *data;
  size_t size;
  uintptr_t offset;

  BinaryFormat format;
  BinaryBitness bitness;
  BinaryEndianness endianness;

  Arena *arena;
} Reader;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

static inline Reader create_reader(const Binary *bin) {
  return (Reader){
      .data = bin->data,
      .size = bin->size,
      .offset = 0,
      .format = bin->format,
      .bitness = bin->bitness,
      .endianness = bin->endianness,
      .arena = bin->arena,
  };
}

#pragma GCC diagnostic pop

BError reader_seek(Reader *reader, size_t new_offset);
BError reader_advance(Reader *reader, size_t amount);
size_t reader_get_offset(const Reader *reader);

BError reader_read_byte(Reader *reader, uint8_t *out_val);
BError reader_read_word(Reader *reader, uint16_t *out_val);
BError reader_read_dword(Reader *reader, uint32_t *out_val);
BError reader_read_qword(Reader *reader, uint64_t *out_val);
BError reader_read_bytes(Reader *reader, uint8_t *out_buf, size_t num_bytes);
BError reader_read_addr(Reader *reader, uint64_t *out_val);

#endif // READER_H
