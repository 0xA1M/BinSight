#ifndef ERROR_H
#define ERROR_H

#include "core/utils.h"

#define BERR_OK                                                                \
  ((BError){.code = OK, .file = NULL, .line = 0, .func = NULL, .err_msg = NULL})

typedef enum : uint8_t {
  // Success
  OK = 0,

  // Generic Errors (0x01->0x0F)
  ERR_UNKNOWN = 0x01,

  // IO and File System Errors (0x10->0x1F)
  ERR_FILE_NOT_FOUND = 0x10,
  ERR_FILE_OPEN_FAILED,
  ERR_FILE_READ_FAILED,
  ERR_FILE_STAT_FAILED,
  ERR_FILE_MMAP_FAILED,
  ERR_FILE_UNMMAP_FAILED,
  ERR_FILE_IS_DIRECTORY,
  ERR_FILE_PERMISSIONS,
  ERR_IO_UNKNOWN,

  // Memory Management Errors (0x20->0x2F)
  ERR_MEM_ALLOC_FAILED = 0x20,
  ERR_MEM_INVALID_ARENA,
  ERR_MEM_OUT_OF_BOUNDS,
  ERR_MEM_ALIGNMENT_INVALID,
  ERR_MEM_UNKNOWN,

  // Format/Parsing Specific Errors (0x30->0x3F)
  ERR_FORMAT_UNKNOWN = 0x30,
  ERR_FORMAT_UNSUPPORTED,
  ERR_FORMAT_HANDLER_NOT_FOUND,
  ERR_FORMAT_MAGIC_INIT_FAILED,
  ERR_FORMAT_MAGIC_LOAD_FAILED,
  ERR_FORMAT_MAGIC_DETECT_FAILED,
  ERR_FORMAT_HEADER_TOO_SMALL,
  ERR_FORMAT_HEADER_MISMATCH,
  ERR_FORMAT_PARSE_FAILED,
  ERR_FORMAT_BAD_INDEX,
  ERR_FORMAT_BAD_OFFSET_SIZE,
  ERR_FORMAT_INVALID_FIELD,
  ERR_FORMAT_CORRUPT_DATA,
  ERR_FORMAT_NULL_PTR,
  ERR_FORMAT_UNKNOWN_ERROR,
  ERR_FORMAT_OUT_OF_BOUNDS,

  // Argument Errors (0x40->0x4F)
  ERR_ARG_NULL = 0x40,
  ERR_ARG_INVALID,
  ERR_ARG_OUT_OF_RANGE,
  ERR_ARG_UNKNOWN,

  // Internal Errors (0xF0->0xFF)
  ERR_INTERNAL_BUG = 0xF0,
  ERR_INTERNAL_UNKNOWN,

  // Max value sentinel
  ERR_MAX_CODE = 0xFF
} BErrorCode;

typedef struct {
  // Error codes
  BErrorCode code;

  // Context
  const char *file;
  const char *func;
  int line;

  // Error Message
  char *err_msg;
} BError;

#define IS_OK(err) ((err).code == OK)
#define IS_ERR(err) ((err).code != OK)

// RET_IF_ERR: For functions returning BError. Propagates the error up.
#define RET_IF_ERR(expr)                                                       \
  do {                                                                         \
    BError _e = (expr);                                                        \
    if (IS_ERR(_e)) {                                                          \
      return _e;                                                               \
    }                                                                          \
  } while (0)

// CHECK: For functions returning BError. Creates and returns a new error if
// condition is false.
#define CHECK(cond, err_code, fmt, ...)                                        \
  do {                                                                         \
    if (!(cond)) {                                                             \
      return berr_new((err_code), fmt, __FILE__, __LINE__, __func__,           \
                      ##__VA_ARGS__);                                          \
    }                                                                          \
  } while (0)

// CHECK_ERRNO: Similar to CHECK, but includes errno description.
#define CHECK_ERRNO(cond, err_code, fmt, ...)                                  \
  do {                                                                         \
    if (!(cond)) {                                                             \
      return berr_from_errno((err_code), fmt, __FILE__, __LINE__, __func__,    \
                             ##__VA_ARGS__);                                   \
    }                                                                          \
  } while (0)

// ASSERT_RET: For functions return void.
#define ASSERT_RET(cond, err_code, fmt, ...)                                   \
  do {                                                                         \
    if (!(cond)) {                                                             \
      BError _e = berr_new((err_code), fmt, __FILE__, __LINE__, __func__,      \
                           ##__VA_ARGS__);                                     \
      berr_print(&_e);                                                         \
      return;                                                                  \
    }                                                                          \
  } while (0)

// ASSERT_RET_VAL: For functions returning non-BError types.
// Creates, prints, and returns a specified value if condition is false.
#define ASSERT_RET_VAL(cond, ret_val, err_code, fmt, ...)                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      BError _e = berr_new((err_code), fmt, __FILE__, __LINE__, __func__,      \
                           ##__VA_ARGS__);                                     \
      berr_print(&_e);                                                         \
      return (ret_val);                                                        \
    }                                                                          \
  } while (0)

// ASSERT_RET_VAL_ERRNO: Similar to ASSERT_RET_VAL, but includes errno
// description.
#define ASSERT_RET_VAL_ERRNO(cond, ret_val, err_code, fmt, ...)                \
  do {                                                                         \
    if (!(cond)) {                                                             \
      BError _e = berr_from_errno((err_code), fmt, __FILE__, __LINE__,         \
                                  __func__, ##__VA_ARGS__);                    \
      berr_print(&_e);                                                         \
      return (ret_val);                                                        \
    }                                                                          \
  } while (0)

// ASSERT_GOTO: For functions with complex cleanup paths (e.g., using goto
// error_label). Creates, prints, and jumps to a label if condition is false.
#define ASSERT_GOTO(cond, label, err_code, fmt, ...)                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      BError _e = berr_new((err_code), fmt, __FILE__, __LINE__, __func__,      \
                           ##__VA_ARGS__);                                     \
      berr_print(&_e);                                                         \
      goto label;                                                              \
    }                                                                          \
  } while (0)

// ASSERT_GOTO_ERRNO: Similar to ASSERT_GOTO, but includes errno
// description.
#define ASSERT_GOTO_ERRNO(cond, label, err_code, fmt, ...)                     \
  do {                                                                         \
    if (!(cond)) {                                                             \
      BError _e = berr_from_errno((err_code), fmt, __FILE__, __LINE__,         \
                                  __func__, ##__VA_ARGS__);                    \
      berr_print(&_e);                                                         \
      goto label;                                                              \
    }                                                                          \
  } while (0)

static const LT_Entry BErrorCodeStrTable[] = {
    // Success
    {OK, "Success: Operation completed successfully"},

    // Generic Errors
    {ERR_UNKNOWN, "Unknown error: An unspecified error occurred"},

    // IO and File System Errors
    {ERR_FILE_NOT_FOUND, "File error: The specified file was not found"},
    {ERR_FILE_OPEN_FAILED, "File error: Failed to open the file"},
    {ERR_FILE_READ_FAILED, "File error: Failed to read from the file"},
    {ERR_FILE_STAT_FAILED, "File error: Failed to retrieve file metadata"},
    {ERR_FILE_MMAP_FAILED, "File error: Failed to memory-map the file"},
    {ERR_FILE_IS_DIRECTORY,
     "File error: Expected a file but found a directory"},
    {ERR_FILE_PERMISSIONS, "File error: Insufficient permissions"},
    {ERR_IO_UNKNOWN, "I/O error: An unspecified input/output error occurred"},

    // Memory Management Errors
    {ERR_MEM_ALLOC_FAILED, "Memory error: Failed to allocate memory"},
    {ERR_MEM_INVALID_ARENA, "Memory error: Invalid memory arena provided"},
    {ERR_MEM_OUT_OF_BOUNDS, "Memory error: Accessed memory out of bounds"},
    {ERR_MEM_ALIGNMENT_INVALID, "Memory error: Invalid memory alignment"},
    {ERR_MEM_UNKNOWN, "Memory error: An unspecified memory error occurred"},

    // Format/Parsing Errors
    {ERR_FORMAT_UNKNOWN, "Format error: Unknown format"},
    {ERR_FORMAT_UNSUPPORTED, "Format error: Unsupported format"},
    {ERR_FORMAT_HANDLER_NOT_FOUND, "Format error: No handler found for format"},
    {ERR_FORMAT_MAGIC_INIT_FAILED,
     "Format error: Failed to initialize magic numbers"},
    {ERR_FORMAT_MAGIC_LOAD_FAILED,
     "Format error: Failed to load magic database"},
    {ERR_FORMAT_MAGIC_DETECT_FAILED,
     "Format error: Failed to detect format via magic"},
    {ERR_FORMAT_HEADER_TOO_SMALL, "Format error: Header size too small"},
    {ERR_FORMAT_HEADER_MISMATCH,
     "Format error: Header does not match expected values"},
    {ERR_FORMAT_PARSE_FAILED, "Format error: Failed while parsing file"},
    {ERR_FORMAT_BAD_INDEX, "Format error: Invalid or out-of-range index"},
    {ERR_FORMAT_BAD_OFFSET_SIZE, "Format error: Invalid offset or size"},
    {ERR_FORMAT_INVALID_FIELD, "Format error: Invalid or corrupt field"},
    {ERR_FORMAT_CORRUPT_DATA, "Format error: Corrupt or inconsistent data"},
    {ERR_FORMAT_NULL_PTR, "Format error: Unexpected NULL pointer encountered"},
    {ERR_FORMAT_UNKNOWN_ERROR,
     "Format error: An unspecified format error occurred"},

    // Argument Errors
    {ERR_ARG_NULL, "Argument error: NULL argument provided"},
    {ERR_ARG_INVALID, "Argument error: Invalid argument value"},
    {ERR_ARG_OUT_OF_RANGE, "Argument error: Argument out of valid range"},
    {ERR_ARG_UNKNOWN, "Argument error: An unspecified argument error occurred"},

    // Internal Errors
    {ERR_INTERNAL_BUG, "Internal error: Unexpected bug encountered"},
    {ERR_INTERNAL_UNKNOWN,
     "Internal error: An unspecified internal error occurred"},

    // Sentinel
    {ERR_MAX_CODE, "Invalid error code (sentinel value)"}};

BError berr_new(BErrorCode code, const char *fmt, const char *file, int line,
                const char *func, ...);
BError berr_from_errno(BErrorCode code, const char *fmt, const char *file,
                       int line, const char *func, ...);

void berr_set_arena(Arena *arena);
const char *berr_code_to_str(BErrorCode code);
const char *berr_msg(const BError *err);

void berr_print(const BError *err);

#endif // ERROR_H
