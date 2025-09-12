#include "gtest/gtest.h"

extern "C" {
#include "core/mem.h"
#include "core/utils.h"
}

class ArenaTest : public ::testing::Test {
protected:
  Arena *test_arena;

  void SetUp() override {
    test_arena = arena_init();
    ASSERT_NE(test_arena, nullptr);
  }

  void TearDown() override {
    arena_destroy(test_arena);
    test_arena = nullptr;
  }
};

// Test case for Arena initialization and destruction
TEST_F(ArenaTest, InitDestroy) {
  Arena *temp_arena = arena_init();
  ASSERT_NE(temp_arena, nullptr);
  arena_destroy(temp_arena);

  arena_destroy(nullptr);
}

// Test case for basic memory allocation from the arena
TEST_F(ArenaTest, Alloc) {
  // Allocate a small block
  void *ptr1 = arena_alloc(test_arena, 10);
  ASSERT_NE(ptr1, nullptr);

  // Allocate another block, ensuring it's a different address
  void *ptr2 = arena_alloc(test_arena, 100);
  ASSERT_NE(ptr2, nullptr);
  ASSERT_NE(ptr1,
            ptr2); // Pointers should be different for distinct allocations

  // Allocate a large block to potentially trigger a new chunk allocation
  void *ptr3 = arena_alloc(test_arena, CHUNK_SIZE * 2);
  ASSERT_NE(ptr3, nullptr);

  // Test zero-sized allocation (should return NULL)
  void *zero_ptr = arena_alloc(test_arena, 0);
  ASSERT_EQ(zero_ptr, nullptr);

  // Test allocation with a NULL arena (should return NULL)
  void *null_arena_ptr = arena_alloc(nullptr, 10);
  ASSERT_EQ(null_arena_ptr, nullptr);
}

// Test case for aligned memory allocation
TEST_F(ArenaTest, AllocAlign) {
  // Test various alignments
  void *ptr_align1 = arena_alloc_align(test_arena, 1, 1);
  ASSERT_NE(ptr_align1, nullptr);
  ASSERT_EQ(reinterpret_cast<uintptr_t>(ptr_align1) % 1, 0);

  void *ptr_align4 = arena_alloc_align(test_arena, 1, 4);
  ASSERT_NE(ptr_align4, nullptr);
  ASSERT_EQ(reinterpret_cast<uintptr_t>(ptr_align4) % 4, 0);

  void *ptr_align8 = arena_alloc_align(test_arena, 1, 8);
  ASSERT_NE(ptr_align8, nullptr);
  ASSERT_EQ(reinterpret_cast<uintptr_t>(ptr_align8) % 8, 0);

  void *ptr_align16 = arena_alloc_align(test_arena, 1, 16);
  ASSERT_NE(ptr_align16, nullptr);
  ASSERT_EQ(reinterpret_cast<uintptr_t>(ptr_align16) % 16, 0);

  // Test invalid alignment (should return NULL)
  void *invalid_align_ptr =
      arena_alloc_align(test_arena, 10, 3); // 3 is not a power of 2
  ASSERT_EQ(invalid_align_ptr, nullptr);

  // Test zero-sized allocation with alignment (should return NULL)
  void *zero_size_align_ptr = arena_alloc_align(test_arena, 0, 8);
  ASSERT_EQ(zero_size_align_ptr, nullptr);

  // Test allocation with NULL arena (should return NULL)
  void *null_arena_align_ptr = arena_alloc_align(nullptr, 10, 8);
  ASSERT_EQ(null_arena_align_ptr, nullptr);
}

// Test case for array allocation
TEST_F(ArenaTest, AllocArray) {
  // Allocate an array of 5 integers
  int *arr1 = static_cast<int *>(arena_alloc_array(test_arena, 5, sizeof(int)));
  ASSERT_NE(arr1, nullptr);

  // Allocate another array
  char *arr2 =
      static_cast<char *>(arena_alloc_array(test_arena, 20, sizeof(char)));
  ASSERT_NE(arr2, nullptr);
  ASSERT_NE(arr1, reinterpret_cast<int *>(arr2));

  // Test zero count allocation (should return nullptr)
  void *zero_count_arr = arena_alloc_array(test_arena, 0, sizeof(int));
  ASSERT_EQ(zero_count_arr, nullptr);

  // Test zero size allocation (should return nullptr)
  void *zero_size_arr = arena_alloc_array(test_arena, 5, 0);
  ASSERT_EQ(zero_size_arr, nullptr);

  // Test integer overflow for count * size (this might be hard to trigger
  // reliably without platform-specific `SIZE_MAX` knowledge or large values)
  // For demonstration, let's assume `SIZE_MAX / 2 + 1` for count and `2` for
  // size to potentially trigger an overflow if SIZE_MAX is sufficiently small.
  // Given the current implementation of arena_alloc_array, this is handled via
  // ASSERT_RET_VAL and would return NULL.
  void *overflow_arr = arena_alloc_array(test_arena, SIZE_MAX / 2 + 1, 2);
  ASSERT_EQ(overflow_arr, nullptr); // Expect NULL due to overflow check

  // Test allocation with a NULL arena
  void *null_arena_arr = arena_alloc_array(nullptr, 5, sizeof(int));
  ASSERT_EQ(null_arena_arr, nullptr);
}

// Test case for string allocation and comparison
TEST_F(ArenaTest, StringNewAndEq) {
  const char *raw_str1 = "Hello";
  const char *raw_str2 = "World";
  const char *raw_str3 = "Hello";
  const char *raw_str4 = "test";
  const char *raw_str5 = "testing";

  // Test string_new and content verification
  String s1 = string_new(test_arena, raw_str1, strlen(raw_str1));
  ASSERT_NE(s1.str, nullptr);
  ASSERT_STREQ(s1.str, raw_str1);
  ASSERT_EQ(s1.len, strlen(raw_str1));
  // Ensure it's a duplicate, not just the same pointer
  ASSERT_NE(s1.str, raw_str1);

  String s2 = string_new(test_arena, raw_str2, strlen(raw_str2));
  ASSERT_NE(s2.str, nullptr);
  ASSERT_STREQ(s2.str, raw_str2);

  String s3 = string_new(test_arena, raw_str3, strlen(raw_str3));
  ASSERT_NE(s3.str, nullptr);
  ASSERT_STREQ(s3.str, raw_str3);

  // Test string_eq with identical strings
  ASSERT_TRUE(string_eq(s1, s3)) << "s1 and s3 (same content) should be equal";

  // Test string_eq with different strings
  ASSERT_FALSE(string_eq(s1, s2))
      << "s1 and s2 (different content) should not be equal";

  // Test with empty strings
  String empty_s1 = string_new(test_arena, "", 0);
  ASSERT_TRUE(IS_STR_EMPTY(empty_s1))
      << "string_new with empty cstr should return EMPTY_STR";
  String empty_s2 = {};
  ASSERT_TRUE(string_eq(empty_s1, empty_s2))
      << "Two empty strings (EMPTY_STR) should be equal";

  // Test string_eq with different lengths but similar prefixes
  String s4 = string_new(test_arena, raw_str4, strlen(raw_str4));
  String s5 = string_new(test_arena, raw_str5, strlen(raw_str5));
  ASSERT_FALSE(string_eq(s4, s5))
      << "Strings with different lengths should not be equal";

  // Test string_new with NULL cstr
  String null_str_input = string_new(test_arena, nullptr, 5);
  ASSERT_TRUE(IS_STR_EMPTY(null_str_input))
      << "string_new with NULL cstr should return EMPTY_STR";

  // Test string_new with NULL arena
  String null_arena_str = string_new(nullptr, "test", 4);
  ASSERT_TRUE(IS_STR_EMPTY(null_arena_str))
      << "string_new with NULL arena should return EMPTY_STR";
}

// Test case for arena_strdup
TEST_F(ArenaTest, ArenaStrdup) {
  const char *original_str = "A duplicated string.";
  size_t len = strlen(original_str);

  const char *duplicated_str = arena_strdup(test_arena, original_str, len);
  ASSERT_NE(duplicated_str, nullptr);
  ASSERT_STREQ(duplicated_str, original_str);
  ASSERT_NE(duplicated_str,
            original_str); // Should be a duplicate, not the same pointer

  // Test with NULL source string
  const char *null_src_strdup = arena_strdup(test_arena, nullptr, 5);
  ASSERT_EQ(null_src_strdup, nullptr);

  // Test with zero length
  const char *zero_len_strdup = arena_strdup(test_arena, "test", 0);
  ASSERT_EQ(zero_len_strdup, nullptr);

  // Test with NULL arena
  const char *null_arena_strdup = arena_strdup(nullptr, original_str, len);
  ASSERT_EQ(null_arena_strdup, nullptr);
}
