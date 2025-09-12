#include "gtest/gtest.h"

extern "C" {
#include "core/error.h"
#include "core/mem.h"
#include <errno.h>
}

class ErrorTest : public ::testing::Test {
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

// Test berr_new function
TEST_F(ErrorTest, BErrorNew) {
  BError err = {};

  // Test BERR_OK
  ASSERT_EQ(err.code, OK);
  ASSERT_TRUE(IS_OK(err));
  ASSERT_FALSE(IS_ERR(err));
  ASSERT_EQ(err.file, nullptr);
  ASSERT_EQ(err.func, nullptr);
  ASSERT_EQ(err.line, 0);
  ASSERT_TRUE(IS_STR_EMPTY(err.err_msg))
      << "BERR_OK should have an empty error message.";

  // Test generic error with message
  err = berr_new(test_arena, ERR_UNKNOWN, "Something went wrong with %s",
                 __FILE__, __LINE__, __func__, "test");
  ASSERT_EQ(err.code, ERR_UNKNOWN);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_STREQ(err.file, __FILE__);
  ASSERT_STREQ(err.func, __func__);
  ASSERT_NE(err.line, 0) << "Line number should be set for a new error.";
  ASSERT_STREQ(berr_msg(&err).str, "[Unknown error: An unspecified error "
                                   "occurred] Something went wrong with test");

  // Test error without message format
  err = berr_new(test_arena, ERR_MEM_ALLOC_FAILED, nullptr, __FILE__, __LINE__,
                 __func__);
  ASSERT_EQ(err.code, ERR_MEM_ALLOC_FAILED);
  ASSERT_STREQ(berr_msg(&err).str, "[Memory error: Failed to allocate memory]");

  // Test berr_new with NULL arena (should return an error indicating allocation
  // failure for err_msg)
  err = berr_new(nullptr, ERR_UNKNOWN, "Test error with NULL arena", __FILE__,
                 __LINE__, __func__);
  ASSERT_EQ(err.code, ERR_MEM_ALLOC_FAILED); // This is the expected error if
                                             // String allocation fails
  ASSERT_TRUE(
      IS_STR_EMPTY(err.err_msg)); // No message allocated if arena is NULL
}

// Test berr_from_errno function
TEST_F(ErrorTest, BErrorFromErrno) {
  BError err;

  // Set a specific errno value for testing
  errno = EACCES; // Permission denied

  // Test error from errno with message
  err = berr_from_errno(test_arena, ERR_FILE_PERMISSIONS, "Failed to access %s",
                        __FILE__, __LINE__, __func__, "file.txt");
  ASSERT_EQ(err.code, ERR_FILE_PERMISSIONS);
  ASSERT_TRUE(IS_ERR(err));
  ASSERT_STREQ(err.file, __FILE__);
  ASSERT_STREQ(err.func, __func__);
  ASSERT_NE(err.line, 0) << "Line number should be set for a new error.";
  ASSERT_STREQ(berr_msg(&err).str,
               "[File error: Insufficient permissions] Failed to access "
               "file.txt: Permission denied");

  // Test error from errno without message format
  errno = ENOENT; // No such file or directory
  err = berr_from_errno(test_arena, ERR_FILE_NOT_FOUND, nullptr, __FILE__,
                        __LINE__, __func__);
  ASSERT_EQ(err.code, ERR_FILE_NOT_FOUND);
  ASSERT_STREQ(berr_msg(&err).str, "[File error: The specified file was not "
                                   "found] No such file or directory");

  // Test berr_from_errno with NULL arena
  errno = ENOMEM;
  err = berr_from_errno(nullptr, ERR_MEM_ALLOC_FAILED,
                        "Test errno with NULL arena", __FILE__, __LINE__,
                        __func__);
  ASSERT_EQ(err.code, ERR_MEM_ALLOC_FAILED);
  ASSERT_TRUE(IS_STR_EMPTY(err.err_msg));
}

// Test berr_code_to_str function
TEST_F(ErrorTest, BErrorCodeToStr) {
  ASSERT_STREQ(berr_code_to_str(OK).str,
               "Success: Operation completed successfully");
  ASSERT_STREQ(berr_code_to_str(ERR_FILE_NOT_FOUND).str,
               "File error: The specified file was not found");
  ASSERT_STREQ(berr_code_to_str(ERR_MEM_ALLOC_FAILED).str,
               "Memory error: Failed to allocate memory");
  ASSERT_STREQ(berr_code_to_str(ERR_FORMAT_UNSUPPORTED).str,
               "Format error: Unsupported format");
  ASSERT_STREQ(berr_code_to_str(ERR_ARG_NULL).str,
               "Argument error: NULL argument provided");
  ASSERT_STREQ(berr_code_to_str(ERR_INTERNAL_BUG).str,
               "Internal error: Unexpected bug encountered");
  ASSERT_STREQ(berr_code_to_str(static_cast<BErrorCode>(99)).str,
               "Unrecognized error code"); // Test an unknown code
}

// Test berr_msg function
TEST_F(ErrorTest, BErrorMsg) {
  BError err_ok = {};
  ASSERT_STREQ(berr_msg(&err_ok).str, "(no error message)");

  BError err_with_msg = berr_new(test_arena, ERR_UNKNOWN, "Test message",
                                 __FILE__, __LINE__, __func__);
  ASSERT_STREQ(berr_msg(&err_with_msg).str,
               "[Unknown error: An unspecified error occurred] Test message");

  // Test with NULL error pointer
  ASSERT_STREQ(berr_msg(nullptr).str, "(no error message)");
}
