#ifndef MEM_H
#define MEM_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#ifndef DEFAULT_ALIGNMENT
#define DEFAULT_ALIGNMENT alignof(max_align_t)
#endif

#ifndef CHUNK_SIZE
#define CHUNK_SIZE (size_t)(4 * 1024) // 4KB default size
#endif

typedef struct Chunk {
  struct Chunk *next;

  size_t cap;
  size_t used;
  uint8_t *data;
} Chunk;

typedef struct {
  Chunk *head;
  Chunk *current;
} Arena;

Arena *arena_init(void);
void arena_destroy(Arena *arena);

void *arena_alloc(Arena *arena, size_t size);
void *arena_alloc_array(Arena *arena, size_t count, size_t size);
void *arena_alloc_align(Arena *arena, size_t size, size_t alignment);
const char *arena_strdup(Arena *arena, const char *str, size_t len);

#endif // MEM_H
