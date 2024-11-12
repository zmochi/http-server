/**
 * @file memblocks.h
 * @brief block-scoped memory manager. manages variable-sized allocations in
 * block of set size, calling malloc() only once chunk size of memory is used
 * up. allows de-allocating used memory and re-using it later in O(1). good for
 * programs that free and allocate the same size of objects many times.
 */

#ifndef __MEMPOOL_ALLOCATOR_H
#define __MEMPOOL_ALLOCATOR_H

#include <src/defs.h> /* _Nullable, _Nonnull */
#include <stddef.h>   /* for size_t */

typedef enum {
    MEM_SUCCESS,
    MEM_FAIL,
    NOMEM,
    MAX_SIZE_EXCEEDED,
} mem_status_t;

/* opaque struct, can only be referenced through pointer */
struct mempool_allocator;

struct mempool_allocator *_Nullable new_mempool_allocator(size_t chunk_size);

void destroy_mempool_allocator(struct mempool_allocator *_Nonnull instance);

void *memblock_alloc(struct mempool_allocator *_Nonnull instance, size_t size);

void memblock_dealloc(struct mempool_allocator *_Nonnull instance,
                      void *_Nonnull block);

#endif /* __MEMPOOL_ALLOCATOR_H */
