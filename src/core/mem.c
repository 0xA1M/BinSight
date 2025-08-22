#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "core/error.h"
#include "core/mem.h"

static uintptr_t align_forward(uintptr_t ptr, size_t alignment) {
  assert(IS_POWER_2(alignment));

  uintptr_t modulo = ptr & (alignment - 1);
  if (modulo != 0)
    ptr += alignment - modulo;

  return ptr;
}

static Chunk *allocate_new_chunk(size_t cap) {
  Chunk *chunk = (Chunk *)calloc(1, sizeof(Chunk) + cap);
  ASSERT_RET_VAL_ERRNO(chunk != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                       "Failed to allocate new chunk with capacity %zu", cap);

  chunk->data = (uint8_t *)(chunk + 1);
  chunk->cap = cap;
  chunk->used = 0;
  chunk->next = NULL;

  return chunk;
}

Arena *arena_init(void) {
  Arena *arena = (Arena *)calloc(1, sizeof(Arena));
  ASSERT_RET_VAL_ERRNO(arena != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                       "Failed to create arena");

  arena->head = allocate_new_chunk(CHUNK_SIZE);
  ASSERT_GOTO(arena->head != NULL, cleanup_arena, ERR_MEM_ALLOC_FAILED,
              "Failed to allocate initial chunk for arena");

  arena->current = arena->head;
  return arena;

cleanup_arena:
  free(arena);
  return NULL;
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
  ASSERT_RET_VAL(arena != NULL, NULL, ERR_ARG_NULL, "Arena pointer is NULL");
  ASSERT_RET_VAL(size > 0, NULL, ERR_ARG_INVALID,
                 "Allocation size must be greater than 0");

  ASSERT_RET_VAL(alignment > 0 && IS_POWER_2(alignment), NULL,
                 ERR_MEM_ALIGNMENT_INVALID,
                 "Alignment must be non-zero power of 2");

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
  ASSERT_RET_VAL(new_chunk != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                 "Failed to allocate new chunk for arena");

  uintptr_t new_ptr = (uintptr_t)new_chunk->data;
  uintptr_t new_aligned = align_forward(new_ptr, alignment);
  size_t new_offset = new_aligned - new_ptr;

  assert(new_offset + size <=
         new_chunk->cap); // Should always be true true to min_cap

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
    ASSERT_RET_VAL(
        false, NULL, ERR_ARG_OUT_OF_RANGE,
        "Integer overflow detected in array allocation (count=%zu, size=%zu)",
        count, size);

  return arena_alloc_align(arena, count * size, DEFAULT_ALIGNMENT);
}

const char *arena_strdup(Arena *arena, const char *str, size_t len) {
  ASSERT_RET_VAL(str != NULL, NULL, ERR_ARG_NULL, "Source string is NULL");
  ASSERT_RET_VAL(len > 0, NULL, ERR_ARG_INVALID,
                 "String length must be greater than 0");

  char *str_dup = (char *)arena_alloc_array(arena, len + 1, sizeof(char));
  ASSERT_RET_VAL(str_dup != NULL, NULL, ERR_MEM_ALLOC_FAILED,
                 "Failed to allocate memory for string duplication");

  memcpy(str_dup, str, len);
  str_dup[len] = '\0';

  return (const char *)str_dup;
}
