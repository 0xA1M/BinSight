#include "gtest/gtest.h"

extern "C" {
#include "core/binary.h"
#include "core/error.h"
#include "core/mem.h"
#include "core/reader.h"
}

class ReaderTest : public ::testing::Test {
protected:
  Arena *test_arena;
  Binary *test_binary;
  uint8_t *test_data;
  size_t test_data_size = 16;

  void SetUp() override {
    test_binary = init_binary();
    ASSERT_NE(test_binary, nullptr);
    test_arena = test_binary->arena;

    test_data = static_cast<uint8_t *>(arena_alloc(test_arena, test_data_size));
    ASSERT_NE(test_data, nullptr);
    // Initialize with some known pattern
    for (size_t i = 0; i < test_data_size; ++i) {
      test_data[i] = static_cast<uint8_t>(i + 1);
    }

    test_binary->data = test_data;
    test_binary->size = test_data_size;
    test_binary->bitness = BITNESS_64; // Default to 64-bit for most tests
    test_binary->endianness = ENDIANNESS_LITTLE; // Default to little endian
  }

  void TearDown() override {
    test_binary->data = nullptr;
    free_binary(test_binary);
    test_binary = nullptr;
    test_arena = nullptr;
    test_data = nullptr;
  }
};

TEST_F(ReaderTest, CreateReader) {
  Reader reader = create_reader(test_binary);
  ASSERT_EQ(reader.data, test_binary->data);
  ASSERT_EQ(reader.size, test_binary->size);
  ASSERT_EQ(reader.offset, 0);
  ASSERT_EQ(reader.format, test_binary->format);
  ASSERT_EQ(reader.bitness, test_binary->bitness);
  ASSERT_EQ(reader.endianness, test_binary->endianness);
  ASSERT_EQ(reader.arena, test_binary->arena);
}

TEST_F(ReaderTest, ReaderSeek) {
  Reader reader = create_reader(test_binary);
  BError err;

  // Valid seek within bounds
  err = reader_seek(&reader, 5);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(reader.offset, 5);

  // Seek to end of buffer
  err = reader_seek(&reader, test_data_size);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(reader.offset, test_data_size);

  // Seek out of bounds (should return error, offset unchanged)
  err = reader_seek(&reader, test_data_size + 1);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
  ASSERT_EQ(reader.offset, test_data_size); // Offset should remain unchanged
}

TEST_F(ReaderTest, ReaderAdvance) {
  Reader reader = create_reader(test_binary);
  BError err;

  // Valid advance
  err = reader_advance(&reader, 5);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(reader.offset, 5);

  // Advance to end of buffer
  err = reader_advance(&reader, test_data_size - 5);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(reader.offset, test_data_size);

  // Advance out of bounds (should return error, offset unchanged)
  err = reader_advance(&reader, 1);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
  ASSERT_EQ(reader.offset, test_data_size); // Offset should remain unchanged
}

TEST_F(ReaderTest, ReaderGetOffset) {
  Reader reader = create_reader(test_binary);
  ASSERT_EQ(reader_get_offset(&reader), 0);

  reader_seek(&reader, 7);
  ASSERT_EQ(reader_get_offset(&reader), 7);
}

TEST_F(ReaderTest, ReaderReadByte) {
  Reader reader = create_reader(test_binary);
  BError err;
  uint8_t val;

  // Read first byte
  err = reader_read_byte(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x01);
  ASSERT_EQ(reader.offset, 1);

  // Read multiple bytes
  reader_seek(&reader, 5);
  err = reader_read_byte(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x06);
  ASSERT_EQ(reader.offset, 6);

  // Read past end of buffer (should error)
  reader_seek(&reader, test_data_size - 1);
  err = reader_read_byte(&reader, &val); // Reads last byte
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x10);
  ASSERT_EQ(reader.offset, test_data_size);

  err = reader_read_byte(&reader, &val); // Attempts to read past end
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
  ASSERT_EQ(reader.offset, test_data_size); // Offset should remain unchanged
}

TEST_F(ReaderTest, ReaderReadWord) {
  Reader reader = create_reader(test_binary);
  BError err;
  uint16_t val;

  // Little Endian
  test_binary->endianness = ENDIANNESS_LITTLE;
  reader = create_reader(test_binary); // Re-create reader to apply endianness

  err = reader_read_word(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x0201); // (data[1] << 8) | data[0]
  ASSERT_EQ(reader.offset, 2);

  // Big Endian
  test_binary->endianness = ENDIANNESS_BIG;
  reader = create_reader(test_binary); // Re-create reader

  err = reader_read_word(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x0102); // (data[0] << 8) | data[1]
  ASSERT_EQ(reader.offset, 2);

  // Read past end of buffer
  reader_seek(&reader, test_data_size - 1); // 1 byte from end
  err = reader_read_word(&reader, &val);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
}

TEST_F(ReaderTest, ReaderReadDword) {
  Reader reader = create_reader(test_binary);
  BError err;
  uint32_t val;

  // Little Endian
  test_binary->endianness = ENDIANNESS_LITTLE;
  reader = create_reader(test_binary);

  err = reader_read_dword(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x04030201);
  ASSERT_EQ(reader.offset, 4);

  // Big Endian
  test_binary->endianness = ENDIANNESS_BIG;
  reader = create_reader(test_binary);

  err = reader_read_dword(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x01020304);
  ASSERT_EQ(reader.offset, 4);

  // Read past end of buffer
  reader_seek(&reader, test_data_size - 3); // 3 bytes from end
  err = reader_read_dword(&reader, &val);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
}

TEST_F(ReaderTest, ReaderReadQword) {
  Reader reader = create_reader(test_binary);
  BError err;
  uint64_t val;

  // Little Endian
  test_binary->endianness = ENDIANNESS_LITTLE;
  reader = create_reader(test_binary);

  err = reader_read_qword(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x0807060504030201ULL);
  ASSERT_EQ(reader.offset, 8);

  // Big Endian
  test_binary->endianness = ENDIANNESS_BIG;
  reader = create_reader(test_binary);

  err = reader_read_qword(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x0102030405060708ULL);
  ASSERT_EQ(reader.offset, 8);

  // Read past end of buffer
  reader_seek(&reader, test_data_size - 7); // 7 bytes from end
  err = reader_read_qword(&reader, &val);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
}

TEST_F(ReaderTest, ReaderReadBytes) {
  Reader reader = create_reader(test_binary);
  BError err;
  uint8_t buf[5];

  // Read valid number of bytes
  err = reader_read_bytes(&reader, buf, 5);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(reader.offset, 5);
  ASSERT_EQ(memcmp(buf, test_data, 5), 0);

  // Read more bytes
  err = reader_read_bytes(&reader, buf, 5);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(reader.offset, 10);
  ASSERT_EQ(memcmp(buf, test_data + 5, 5), 0);

  // Read past end of buffer
  err = reader_read_bytes(&reader, buf, 7); // 6 bytes remaining
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_EQ(err.code, ERR_FORMAT_OUT_OF_BOUNDS);
  ASSERT_EQ(reader.offset, 10); // Offset should not change
}

TEST_F(ReaderTest, ReaderReadAddr) {
  Reader reader = create_reader(test_binary);
  BError err;
  uint64_t val;

  // 64-bit address
  test_binary->bitness = BITNESS_64;
  test_binary->endianness = ENDIANNESS_LITTLE;
  reader = create_reader(test_binary);

  err = reader_read_addr(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x0807060504030201ULL);
  ASSERT_EQ(reader.offset, 8);

  // 32-bit address
  test_binary->bitness = BITNESS_32;
  test_binary->endianness = ENDIANNESS_LITTLE;
  reader = create_reader(test_binary);

  err = reader_read_addr(&reader, &val);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_EQ(val, 0x04030201ULL);
  ASSERT_EQ(reader.offset, 4);

  // Read past end (64-bit)
  test_binary->bitness = BITNESS_64;
  reader = create_reader(test_binary);
  reader_seek(&reader, test_data_size - 7); // 7 bytes from end, needs 8
  err = reader_read_addr(&reader, &val);
  ASSERT_TRUE(IS_ERR(err));

  // Read past end (32-bit)
  test_binary->bitness = BITNESS_32;
  reader = create_reader(test_binary);
  reader_seek(&reader, test_data_size - 3); // 3 bytes from end, needs 4
  err = reader_read_addr(&reader, &val);
  ASSERT_TRUE(IS_ERR(err));
}
