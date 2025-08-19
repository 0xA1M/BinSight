#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/mem.h"
#include "core/utils.h"

static uintptr_t align_forward(uintptr_t ptr, size_t alignment) {
  assert(IS_POWER_2(alignment));

  uintptr_t modulo = ptr & (alignment - 1);
  if (modulo != 0)
    ptr += alignment - modulo;

  return ptr;
}

static Chunk *allocate_new_chunk(size_t cap) {
  Chunk *chunk = (Chunk *)calloc(1, sizeof(Chunk) + cap);
  if (chunk == NULL) {
    fprintf(stderr, "Failed to allocated new chunk with capacity %zu: %s\n",
            cap, strerror(errno));
    return NULL;
  }

  chunk->data = (uint8_t *)(chunk + 1);
  chunk->cap = cap;
  chunk->used = 0;
  chunk->next = NULL;

  return chunk;
}

Arena *arena_init(void) {
  Arena *arena = (Arena *)calloc(1, sizeof(Arena));
  if (arena == NULL) {
    fprintf(stderr, "Failed to create arena: %s", strerror(errno));
    return NULL;
  }

  arena->head = allocate_new_chunk(CHUNK_SIZE);
  if (arena->head == NULL) {
    free(arena);
    return NULL;
  }

  arena->current = arena->head;
  return arena;
}

void arena_destroy(Arena *arena) {
  if (arena == NULL)
    return;

  Chunk *chunk = arena->head;
  while (chunk != NULL) {
    Chunk *next_chunk = chunk->next;
    free(chunk);
    chunk = next_chunk;
  }

  free(arena);
}

void *arena_alloc_align(Arena *arena, size_t size, size_t alignment) {
  if (arena == NULL || size == 0)
    return NULL;

  if (alignment == 0 || !IS_POWER_2(alignment)) {
    fprintf(stderr, "Alignment must be non-zero power of 2!\n");
    return NULL;
  }

  uintptr_t cur_ptr = (uintptr_t)arena->current->data + arena->current->used;
  uintptr_t aligned_ptr = align_forward(cur_ptr, alignment);
  size_t offset = aligned_ptr - (uintptr_t)arena->current->data;

  if (offset + size <= arena->current->cap) {
    arena->current->used = offset + size;
    return (void *)aligned_ptr;
  }

  size_t min_cap = size + alignment - 1;
  size_t cap = MAX(min_cap, CHUNK_SIZE);
  Chunk *new_chunk = (Chunk *)allocate_new_chunk(cap);
  if (new_chunk == NULL)
    return NULL;

  uintptr_t new_ptr = (uintptr_t)new_chunk->data;
  uintptr_t new_aligned = align_forward(new_ptr, alignment);
  size_t new_offset = new_aligned - new_ptr;

  assert(new_offset + size <= new_chunk->cap);

  new_chunk->used = new_offset + size;
  arena->current->next = new_chunk;
  arena->current = new_chunk;

  return (void *)new_aligned;
}

void *arena_alloc(Arena *arena, size_t size) {
  return arena_alloc_align(arena, size, DEFAULT_ALIGNMENT);
}

void *arena_alloc_array(Arena *arena, size_t count, size_t size) {
  if (count > 0 && size > SIZE_MAX / count)
    return NULL;

  return arena_alloc_align(arena, count * size, DEFAULT_ALIGNMENT);
}

const char *arena_strdup(Arena *arena, const char *str, size_t len) {
  if (str == NULL)
    return NULL;

  char *str_dup = (char *)arena_alloc_array(arena, len + 1, sizeof(char));
  if (str_dup == NULL)
    return NULL;

  memcpy(str_dup, str, len);
  str_dup[len] = '\0';

  return (const char *)str_dup;
}
