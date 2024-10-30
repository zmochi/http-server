/**
 * @file memblocks.h
 * @brief block-scoped memory manager. manages externally allocated memory in
 * user-specified block sizes
 */

#include <stddef.h> /* for size_t */

/* opaque struct, can only be referenced through pointer */
struct memblocks_module;

struct memblocks_module *new_memblock_instance(void);

void *memblock_alloc(struct memblocks_module *instance, size_t size);

void memblock_dealloc(struct memblocks_module *instance, void *block);
