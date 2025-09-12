#include <string.h>

#include "core/reader.h"

#define CHECK_BOUNDS(reader, read_size)                                        \
  CHECK((reader)->arena, (reader)->offset + (read_size) <= (reader)->size,     \
        ERR_FORMAT_OUT_OF_BOUNDS,                                              \
        "Read of %zu bytes at offset %zu would exceed buffer size %zu",        \
        (size_t)(read_size), (reader)->offset, (reader)->size)

BError reader_seek(Reader *reader, size_t new_offset) {
  CHECK(reader->arena, new_offset <= reader->size, ERR_FORMAT_OUT_OF_BOUNDS,
        "Seek to offset %zu is outside buffer size %zu", new_offset,
        reader->size);
  reader->offset = new_offset;
  return BERR_OK;
}

BError reader_advance(Reader *reader, size_t amount) {
  CHECK_BOUNDS(reader, amount);
  reader->offset += amount;
  return BERR_OK;
}

size_t reader_get_offset(const Reader *reader) { return reader->offset; }

BError reader_read_byte(Reader *reader, uint8_t *out_val) {
  CHECK_BOUNDS(reader, BYTE);
  *out_val = read_byte(reader->data, reader->offset);
  reader->offset += BYTE;
  return BERR_OK;
}

BError reader_read_word(Reader *reader, uint16_t *out_val) {
  CHECK_BOUNDS(reader, WORD);
  *out_val = read_word(reader->data, reader->offset, reader->endianness);
  reader->offset += WORD;
  return BERR_OK;
}

BError reader_read_dword(Reader *reader, uint32_t *out_val) {
  CHECK_BOUNDS(reader, DWORD);
  *out_val = read_dword(reader->data, reader->offset, reader->endianness);
  reader->offset += DWORD;
  return BERR_OK;
}

BError reader_read_qword(Reader *reader, uint64_t *out_val) {
  CHECK_BOUNDS(reader, QWORD);
  *out_val = read_qword(reader->data, reader->offset, reader->endianness);
  reader->offset += QWORD;
  return BERR_OK;
}

BError reader_read_bytes(Reader *reader, uint8_t *out_buf, size_t num_bytes) {
  CHECK_BOUNDS(reader, num_bytes);
  memcpy(out_buf, reader->data + reader->offset, num_bytes);
  reader->offset += num_bytes;
  return BERR_OK;
}

BError reader_read_addr(Reader *reader, uint64_t *out_val) {
  if (reader->bitness == BITNESS_32) {
    uint32_t val32 = 0;
    RET_IF_ERR(reader_read_dword(reader, &val32));
    *out_val = val32;
    return BERR_OK;
  }

  RET_IF_ERR(reader_read_qword(reader, out_val));
  return BERR_OK;
}
