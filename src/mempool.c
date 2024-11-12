#include <assert.h>
#include <src/defs.h> /* for KB, likely/unlikely */
#include <src/freelist.h>
#include <src/list.h>
#include <src/mempool.h>
#include <src/mempool_allocator.h>

#include <stdalign.h>
#include <stddef.h> /* for size_t */
#include <stdlib.h> /* for malloc, realloc */
#include <string.h>

constexpr short MEMPOOL_CHILDREN_PER_NODE = 8;
/* struct for managing parent-child hierarchy within mempools.
 * each mempool contains MEMPOOL_CHILDREN_PER_NODE child mempools statically.
 * if more children are needed, dynamically allocate another struct
 * mempool_children_node and manage with linked list */
struct mempool_children_node {
    struct mempool  *children[MEMPOOL_CHILDREN_PER_NODE];
    int              num_children;
    struct list_item entry;
};

static void init_children_node(struct mempool_children_node *node) {
    init_entry(&node->entry);
    node->num_children = 0;
}

struct mempool {
    struct mempool_children_node children;
};

static void init_mempool(struct mempool *mempool) {
    init_children_node(&mempool->children);
}

static void mempool_add_child(struct mempool *_Nonnull parent,
                              struct mempool *_Nonnull child) {
    struct mempool_children_node *children = &parent->children;

    if ( children->num_children >= MEMPOOL_CHILDREN_PER_NODE ) {
        struct mempool_children_node *new_node =
            mempool_alloc(parent, sizeof(*children));
        init_children_node(new_node);
        list_add_head(&new_node->entry, &children->entry);
        children = new_node;
    }

    children->children[children->num_children++] = child;
}

/*
 * user requests new memory pool
 * memory pool is created. user can allocate variable sized memory from the
 * pool. internally, user is allocated a memory block of size rounded up to the
 * nearest power of 2 from the size requested.
 * memory block is given by global bucket of blocks of the rounded size.
 *
 * mempool module also features a parent-child hierarchy between memory pools,
 * freeing all child memory pools when a parent is freed
 */

/* collect all module data in a single struct for extensibility and readbility
 */
struct mempool_module {
    struct mempool_allocator *memblock_module;
};

struct mempool_module module;

int initialize_mempool_module(void) {
    module.memblock_module = new_mempool_allocator();
}

/* used module interface in server.c to allocate memory - just implement now.
 * maybe allow user to allocate variable sized memory at any time from memory
 * pool and resize exponentially */
struct mempool *_Nullable new_mempool(struct mempool *_Nullable parent) {
    struct mempool *new_pool = memblock_alloc(sizeof(*new_pool));

    init_mempool(new_pool);
    init_children_node(&new_pool->children);

    if ( parent != nullptr ) mempool_add_child(parent, new_pool);

    return new_pool;
}

int destroy_mempool(struct mempool *_Nonnull mempool) {}
