/**
 * @file memblocks.h
 * @brief block-scoped memory manager. manages variable-sized allocations in
 * block of set size, calling malloc() only once chunk size of memory is used
 * up. allows de-allocating used memory and re-using it later in O(1). good for
 * programs that free and allocate the same size of objects many times.
 */

#include <stddef.h> /* for size_t */

typedef enum {
    MEM_SUCCESS,
    NOMEM,
    MAX_SIZE_EXCEEDED,
} mem_status_t;

/* opaque struct, can only be referenced through pointer */
struct memblock_allocator;

struct memblock_allocator *__nullable new_memblock_allocator(size_t chunk_size);

void destroy_memblock_allocator(struct memblock_allocator *__nonnull instance);

void *memblock_alloc(struct memblock_allocator *__nonnull instance,
                     size_t                               size);

void memblock_dealloc(struct memblock_allocator *__nonnull instance,
                      void *__nonnull                      block);
