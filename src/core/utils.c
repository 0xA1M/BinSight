#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "core/format.h"
#include "core/utils.h"

BinaryFormat get_binary_format(Arena *arena, const char *mime_str) {
  ASSERT_RET_VAL(arena, mime_str != NULL, FORMAT_UNKNOWN, ERR_FORMAT_UNKNOWN,
                 "Unknown binary file format");

  if (strncmp(mime_str, X_EXEC, CSTR_LEN(X_EXEC)) == 0 ||
      strncmp(mime_str, X_PIE_EXEC, CSTR_LEN(X_PIE_EXEC)) == 0 ||
      strncmp(mime_str, X_SHAREDLIB, CSTR_LEN(X_SHAREDLIB)) == 0)
    return FORMAT_ELF;

  if (strncmp(mime_str, X_MACH_BIN, CSTR_LEN(X_MACH_BIN)) == 0)
    return FORMAT_MACHO;

  if (strncmp(mime_str, X_DOSEXEC, CSTR_LEN(X_DOSEXEC)) == 0 ||
      strncmp(mime_str, X_PORTEXEC, CSTR_LEN(X_PORTEXEC)) == 0)
    return FORMAT_PE;

  return FORMAT_UNKNOWN;
}

const char *lookup_binary_format(BinaryFormat fmt) {
  switch (fmt) {
  case FORMAT_ELF:
    return "ELF";
  case FORMAT_PE:
    return "PE";
  case FORMAT_MACHO:
    return "MACHO";
  case FORMAT_UNKNOWN:
  default:
    return "unknown";
  }
}

void print_section_hex_dump(Arena *arena, const char *section_name,
                            const uint8_t *buffer, size_t size,
                            const uintptr_t section_offset) {
  ASSERT_RET(arena, buffer != NULL && size != 0, ERR_FORMAT_UNKNOWN,
             "Cannot dump section '%s': buffer is NULL or size is 0",
             section_name ? section_name : "UNKNOWN");

  const size_t line_len = 16;

  printf("\nHex dump of section '%s':\n",
         section_name ? section_name : "UNKNOWN");
  for (size_t i = 0; i < size; i++) {
    // Print address at the start of each line
    if (i % line_len == 0)
      printf("  0x%016lx ", (unsigned long)(section_offset + i));

    printf("%02x", buffer[i]);
    if ((i + 1) % 4 == 0 && (i + 1) % line_len != 0)
      printf(" ");

    if ((i + 1) % line_len == 0 || (i + 1) == size) {
      size_t remaining_bytes = line_len - ((i + 1) % line_len);
      if ((i + 1) == size && remaining_bytes != line_len) {
        size_t printed_hex_chars = (line_len - remaining_bytes) * 2;
        printed_hex_chars += (line_len - remaining_bytes) / 4;

        size_t total_hex_chars_needed = line_len * 2 + (line_len / 4) - 1;
        size_t padding_needed = total_hex_chars_needed - printed_hex_chars;

        for (size_t j = 0; j < padding_needed; j++)
          printf(" ");
      }

      printf(" ");
      printf("|");

      size_t start_of_line = (i / line_len) * line_len;
      for (size_t k = start_of_line; k <= i; k++) {
        if (isprint(buffer[k]))
          printf("%c", buffer[k]);
        else
          printf(".");
      }
      printf("\n");
    }
  }
}

void print_buffer_hex_dump(Arena *arena, const uint8_t *buffer, size_t size,
                           const uintptr_t start_address) {
  ASSERT_RET(arena, buffer != NULL && size != 0, ERR_FORMAT_UNKNOWN,
             "Buffer is NULL or size is 0. Nothing to dump");

  const size_t line_len = 16;

  for (size_t i = 0; i < size; i++) {
    if (i % line_len == 0)
      printf("  0x%016lx ", (unsigned long)(start_address + i));

    printf("%02x", buffer[i]);
    if ((i + 1) % 4 == 0 && (i + 1) % line_len != 0)
      printf(" ");

    if ((i + 1) % line_len == 0 || (i + 1) == size) {
      size_t remaining_bytes_in_line = line_len - ((i + 1) % line_len);
      if ((i + 1) == size && remaining_bytes_in_line != line_len) {
        size_t bytes_printed_on_this_line = (i % line_len) + 1;
        size_t hex_chars_printed_on_this_line = bytes_printed_on_this_line * 2;
        hex_chars_printed_on_this_line += (bytes_printed_on_this_line / 4);

        size_t padding_needed = (line_len * 2 + (line_len / 4 - 1)) -
                                hex_chars_printed_on_this_line;

        for (size_t j = 0; j < padding_needed; j++)
          printf(" ");
      }

      printf(" ");
      printf("|");

      // Print ASCII characters
      size_t start_of_ascii_line = (i / line_len) * line_len;
      for (size_t k = start_of_ascii_line; k <= i; k++) {
        if (isprint(buffer[k]))
          printf("%c", buffer[k]);
        else
          printf(".");
      }
      printf("\n");
    }
  }
}
