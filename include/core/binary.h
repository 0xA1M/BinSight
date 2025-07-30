#ifndef BINARY_H
#define BINARY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct FormatHandler FormatHandler;

typedef enum BinaryBitness {
  BITNESS_UNKNOWN,
  BITNESS_32,
  BITNESS_64
} BinaryBitness;

typedef enum BinaryEndianness {
  ENDIANNESS_UNKNOWN,
  ENDIANNESS_LITTLE,
  ENDIANNESS_BIG,
} BinaryEndianness;

typedef enum BinaryFormat {
  FORMAT_ELF,
  FORMAT_PE,
  FORMAT_MACHO,
  FORMAT_UNKNOWN
} BinaryFormat;

typedef struct BinaryFile {
  char *path;
  BinaryFormat format;
  BinaryBitness bitness;
  BinaryEndianness endianness;

  // Raw binary data
  uint8_t *data;
  size_t size;

  // Metadata
  char *arch;
  bool has_nx;
  bool has_relro;
  bool is_pie;
  bool has_canary;
  bool is_stripped;
  bool has_dwarf;
  char *build_id;

  // Format-specific parsed data.
  void *parsed;

  // Handler
  const FormatHandler *handler;
} BinaryFile;

BinaryFile *init_binary(const char *path, const BinaryFormat fmt,
                        uint64_t f_size);
void free_binary(BinaryFile *bin);

#endif // BINARY_H
