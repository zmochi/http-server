/**
 * @file memblocks.c
 * @brief block-scoped memory manager. manages allocated memory in
 * user-specified block sizes
 */

#include "../src/memblocks.h"
#include "../src/defs.h" /* _Nullable, _Nonnull */
#include "../src/list.h"

#include <assert.h>
#include <errno.h>
#include <math.h> /* for log2() */
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h> /* size_t */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memset */

#define ERROR(msg) printf(msg), exit(1);

typedef size_t blk_size_t;

/* typedef that allows doing byte-precision pointer arithmetic on mem* */
typedef unsigned char mem;

constexpr size_t MAX_ALIGN = alignof(max_align_t);

struct block_data;

static mem_status_t new_block(struct memblock_allocator *module,
                              struct block_data **metadata, blk_size_t size);
static void         bucket_store(struct memblock_allocator *module,
                                 struct block_data         *block);
static struct block_data *_Nullable bucket_retrieve(
    struct memblock_allocator *_Nonnull module, blk_size_t size);
static struct block_data *get_memblock_metadata(const mem *startaddr);
static mem *get_memblock_startaddr(const struct block_data *memblock);
static inline struct bucket_node **_Nonnull get_module_bucket(
    struct memblock_allocator *_Nonnull module, blk_size_t size);

struct block_data {
    blk_size_t size;
    /* this causes the block itself, which appears immediately after this struct
     * in memory, to be aligned to MAX_ALIGN automatically */
    alignas(MAX_ALIGN) char padding[0];
};

static void init_block_data(struct block_data *memblock, blk_size_t size) {
    memblock->size = size;
}

struct memchunk {
    mem           *startaddr;
    _Atomic(mem *) top;
    size_t         total_size;
    /* linked list entry to chain chunks together */
    struct list_item entry;
    /* this causes the chunk itself, which appears immediately after this struct
     * in memory, to be aligned to MAX_ALIGN automatically */
    alignas(MAX_ALIGN) char padding[0];
};

static void init_memchunk(struct memchunk *chunk, mem *startaddr,
                          size_t total_size) {
    chunk->startaddr = startaddr;
    chunk->top = chunk->startaddr;
    chunk->total_size = total_size;

    init_entry(&chunk->entry);
}

static mem *CHUNK_END_PTR(struct memchunk *chunk) {
    /* ensure ptr to start of chunk has byte-precision pointer arithmetic to
     * perform the calculation at end */
    static_assert(sizeof(*chunk->startaddr) == 1);
    return chunk->startaddr + chunk->total_size;
}

static bool is_chunk_full(struct memchunk *chunk, blk_size_t size) {
    /* see CHUNK_END_PTR() note */
    static_assert(sizeof(*chunk->top) == 1);
    auto top = atomic_load_explicit(&chunk->top, memory_order_relaxed);
    return top + size > CHUNK_END_PTR(chunk);
}

/**
 * @brief allocates a new chunk of size @size using a direct call to malloc()
 *
 * @param oldchunk old chunk to chain to this chunk, or NULL if this is the
 * first chunk
 * @param size size of the chunk
 * @return pointer to the memchunk struct, which contains the pointer to actual
 * chunk data or nullptr when out of memory (malloc fails)
 */
static struct memchunk *_Nullable new_memchunk(struct memchunk *oldchunk,
                                               size_t           size) {
    /* the memchunk metadata sits right before the actual chunk. this
     * implementation detail should be hidden.
     * struct memchunk end is aligned to max alignment (in def), so the data
     * segment is aligned */
    struct memchunk *new_chunk = malloc(sizeof(*new_chunk) + size);

    if ( new_chunk == nullptr ) return nullptr;

    init_memchunk(new_chunk, (mem *)new_chunk + sizeof(*new_chunk), size);

    /* logic check */
    assert(new_chunk->startaddr - (mem *)new_chunk == sizeof(struct memchunk));

    if ( oldchunk != nullptr ) [[clang::likely]] {
        list_add_head(&new_chunk->entry, &oldchunk->entry);
    }

    return new_chunk;
}

static void destroy_memchunk(struct memchunk *chunk) { free(chunk); }

/* memory blocks have sizes from the set {2^MEMBLOCKS_MIN_EXP, ...,
 * 2^MEMBLOCKS_MAX_EXP} */
constexpr auto MEMBLOCKS_MAX_EXP = 30; // max 1gb
constexpr auto MEMBLOCKS_MIN_EXP = 0;
constexpr auto MEMBLOCKS_NUM_LISTS = MEMBLOCKS_MAX_EXP - MEMBLOCKS_MIN_EXP + 1;

constexpr auto BUCKET_NODE_SIZE = 8;
/* each bucket is a linked list, each linked list node contains BUCKET_NODE_SIZE
 * blocks available for re-use */
struct bucket_node {
    /* BUCKET_NODE_SIZE should be optimized to around cacheline size. a size of
     * 8 (=BUCKET_NODE_SIZE) where each slot is an 8 byte pointer makes 64 bytes
     * which is a common size of a cacheline */
    struct block_data *blocks[BUCKET_NODE_SIZE];
    /* index of last legal block in blocks array */
    atomic_short top_block;
    /* nodes are stored in linked list */
    struct list_item entry;
};

/**
 * @brief initializer for struct bucket_node
 *
 * @param node pointer to node to initialize
 */
static void init_bucket_node(struct bucket_node *node) {
    node->top_block = 0;
    init_entry(&node->entry);
}

static void
remove_bucket_node([[maybe_unused]] struct memblock_allocator *module,
                   struct bucket_node                         *node) {
    /* must be called under lock for node, no concurrent access is allowed */
    assert(node->top_block == 0);
    list_rm(&node->entry);
}

static void add_bucket_node([[maybe_unused]] struct memblock_allocator *module,
                            struct bucket_node **_Nonnull bucket,
                            struct bucket_node *node) {
    /* must be called under lock for node, no concurrent access is allowed */
    if ( *bucket == nullptr )
        *bucket = node;
    else
        list_add_tail(&node->entry, &((*bucket)->entry));
}

/**
 * @brief creates a new bucket node and appends it to node list in module
 * must be called uner lock for buckets linked list
 *
 * @param module module to allocate memory from and add node to
 * @param bucket pointer to where the first node of the list is stored, points
 * to nullptr if list is empty.
 * @return pointer to the new node, or nullptr if malloc() fails
 */
static struct bucket_node *_Nullable new_bucket_node(
    struct memblock_allocator *_Nonnull module,
    struct bucket_node **_Nonnull bucket) {
    struct bucket_node *new_node;
    struct block_data  *new_node_block;

    new_node_block = bucket_retrieve(module, sizeof(*new_node));

    if ( new_node_block == nullptr ) {
        switch (
            new_block(module, &new_node_block, sizeof(struct bucket_node)) ) {
            case MEM_SUCCESS:
                break;

            case NOMEM:
                return nullptr;

            case MAX_SIZE_EXCEEDED:
                [[fallthrough]];
            default:
                /* unknown return value / max size should not be exceeded in
                 * this allocation. module initialization should check that
                 * there is enough space for a bucket node struct */
                assert(true); // NOLINT clang-tidy assumes incorrectly this can
                              // be changed to static_assert()
        }
    }

    new_node = (struct bucket_node *)get_memblock_startaddr(new_node_block);
    printf("initializing new node at addr %p\n", new_node);
    init_bucket_node(new_node);

    return new_node;
}

static struct bucket_node *_Nullable get_last_bucket_node(
    struct memblock_allocator *_Nonnull module, blk_size_t size) {

    struct bucket_node **bucket = get_module_bucket(module, size);
    struct bucket_node  *last_bucket_node;

    if ( *bucket == nullptr ) {
        last_bucket_node = nullptr;
    } else {
        last_bucket_node =
            list_entry((*bucket)->entry.prev, typeof(*last_bucket_node), entry);
    }

    return last_bucket_node;
}

/* represents a set of buckets, one bucket for each allowed, allocate-able size
 */
struct mempool_buckets {
    /* buckets[i] stores blocks of size 2^(i+MEMBLOCKS_MIN_EXP)
     * buckets[i] is a pointer to a doubly linked list bucket node, or nullptr
     * if there are no items in list (no memblocks stored) */
    struct bucket_node *_Nullable head[MEMBLOCKS_NUM_LISTS];
};

/**
 * @brief initializer for struct memblock_buckets
 *
 * @param buckets pointer to struct to initialize
 */
static void init_memblock_buckets(struct mempool_buckets *buckets) {
    for ( int i = 0; i < MEMBLOCKS_NUM_LISTS; i++ )
        buckets->head[i] = nullptr;
}

struct memblock_allocator {
    /* active chunk.
     * must be atomic - see @ondemand_newchunk() */
    _Atomic(struct memchunk *) cur_chunk;
    /* array of memblock lists, each list contains memory blocks of some size
     * that can be re-used */
    struct mempool_buckets buckets;
    size_t                 chunk_size;
    pthread_mutex_t        bucket_lock;
    pthread_mutex_t        memchunk_lock;
};

/**
 * @brief initializer for struct memblock_allocator, allocates space for the
 * struct as well
 *
 * @return pointer to new memblock_allocator struct, or nullptr if chunk_size is
 * too small
 */
struct memblock_allocator *_Nullable new_memblock_allocator(size_t chunk_size) {
    if ( chunk_size < sizeof(struct block_data) ||
         chunk_size < sizeof(struct bucket_node) ) {
        ERROR("chunk size is too small");
        return nullptr;
    }

    struct memblock_allocator *module = malloc(sizeof(*module));
    struct memchunk           *first_chunk = new_memchunk(nullptr, chunk_size);
    module->cur_chunk = first_chunk;
    module->chunk_size = chunk_size;
    /* TODO: check return value of pthread_mutex_init() */
    /* must be recursive since can't avoid bucket_store calling bucket_retrieve
     */
    pthread_mutexattr_t recursive_mutex;
    pthread_mutexattr_init(&recursive_mutex);
    pthread_mutexattr_settype(&recursive_mutex, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&module->bucket_lock, &recursive_mutex);
    pthread_mutex_init(&module->memchunk_lock, nullptr);

    init_memblock_buckets(&module->buckets);

    return module;
}

void destroy_memblock_allocator(struct memblock_allocator *_Nonnull instance) {
    /* TODO: for list_item in list... */
    destroy_memchunk(instance->cur_chunk);
    free(instance);
}

/**
 * @brief returns the index of next legal block that matches size
 *
 * @param size unmodified size of memory, must be > 0
 * @return see @brief
 */
static blk_size_t block_index(blk_size_t size) {
    assert(size > 0);

    /* about the casting of `size` to double:
     * - at such large values where `size` loses precision, the next power of 2
     * is likely to be the same whether precision is lost or not.
     * - size is very unlikely to be so large the cast makes a difference.
     */
    unsigned int next_exp = (unsigned int)log2((double)size);

    if ( next_exp > MEMBLOCKS_MAX_EXP ) {
        // TODO illegal size
    }

    return (blk_size_t)next_exp;
}

/**
 * @brief getter for struct memblock_allocator
 *
 * @param module pointer to module
 * @return pointer to the module's buckets struct
 */
static inline struct bucket_node **_Nonnull get_module_bucket(
    struct memblock_allocator *_Nonnull module, blk_size_t size) {
    return &module->buckets.head[block_index(size)];
}

/**
 * @brief rounds @size up to nearest size allowed to be allocated in a chunk
 *
 * @param size size to round, must be > 0
 * @return rounded size
 */
static blk_size_t round_to_block(blk_size_t size) {
    assert(size > 0);

    unsigned int next_exp = (unsigned int)block_index(size);

    /* the result of pow() is guaranteed to be an integer, cast is legal */
    unsigned int rounded_val = (unsigned int)pow(2, next_exp);

    return (blk_size_t)rounded_val;
}

/**
 * @brief stores a memory block for later re-use in pool
 *
 * @param bucket pointer to bucket struct to store block in
 * @param block pointer to block to store
 */
static void bucket_store(struct memblock_allocator *_Nonnull module,
                         struct block_data *_Nonnull block) {
    /* this definitely needs refactoring along with all the helper functions
     * used here pls help */

    struct bucket_node **bucket = get_module_bucket(module, block->size);
    struct bucket_node  *last_bucket_node;

    pthread_mutex_lock(&module->bucket_lock);

    last_bucket_node = get_last_bucket_node(module, block->size);
    if ( last_bucket_node == nullptr ||
         last_bucket_node->top_block >= BUCKET_NODE_SIZE ) {
        /* new_bucket_node is expensive, calls new_block() but is
         * called infrequently (frequency of 1/BUCKET_NODE_SIZE) */
        last_bucket_node = new_bucket_node(module, bucket);
        if ( last_bucket_node == nullptr ) {
            // out of memory
            printf("out of memory\n");
            exit(1);
        }
        add_bucket_node(module, bucket, last_bucket_node);
    }

    auto *node_top = &last_bucket_node->top_block;
    // assert(*node_top >= 0 && *node_top < BUCKET_NODE_SIZE);

    /* add block to last bucket */
    last_bucket_node->blocks[(*node_top)++] = block;
    printf("%p: incremented bucket %zu to %d\n", pthread_self(),
           round_to_block(block->size), *node_top);

    pthread_mutex_unlock(&module->bucket_lock);
}

static struct block_data *_Nullable bucket_retrieve(
    struct memblock_allocator *_Nonnull module, blk_size_t size) {
    struct bucket_node *last_bucket_node;
    struct block_data  *block;

    pthread_mutex_lock(&module->bucket_lock);

    /* load without lock since first node's location is constant */
    last_bucket_node = get_last_bucket_node(module, size);
    /* node doesn't exist */
    if ( last_bucket_node == nullptr ) {
        block = nullptr;
    } else {
        block = last_bucket_node->blocks[--last_bucket_node->top_block];
        printf("%p: decremented bucket %zu to %d\n", pthread_self(),
               round_to_block(size), last_bucket_node->top_block);

        if ( last_bucket_node->top_block == 0 ) {
            remove_bucket_node(module, last_bucket_node);
            assert(last_bucket_node->top_block >= 0 &&
                   last_bucket_node->top_block < BUCKET_NODE_SIZE);
            /* return block for re-use */
            bucket_store(module,
                         get_memblock_metadata((mem *)last_bucket_node));
        }
    }

    pthread_mutex_unlock(&module->bucket_lock);

    return block;
}

/**
 * @brief checks if @ptr is aligned to @alignment
 *
 * @param ptr ptr to check
 * @param alignment required alignment
 * @return false if not aligned, true if aligned
 */
[[maybe_unused]] static bool is_aligned(const mem *ptr, size_t alignment) {
    return (((uintptr_t)ptr) % alignment) == 0;
}

/**
 * @brief aligns memory size to specified alignment
 *
 * @param size size to align
 * @param alignment required alignment, typically returned by alignof()
 * @return aligned size
 */
[[maybe_unused]] static blk_size_t align_size(blk_size_t size,
                                              size_t     alignment) {
    return size + (size % alignment);
}

/**
 * @brief calculates and returns ptr to start of user-data belonging to
 * @memblock
 *
 * @param memblock relevant memblock
 * @return see @brief
 */
static mem *get_memblock_startaddr(const struct block_data *memblock) {
    /* see get_memblock_metadata for block_align_size explanation */
    return (mem *)((mem *)memblock + sizeof(*memblock));
}

/* */
/**
 * @brief calculates and returns pointer to block metadata belonging to
 * user-data @startaddr
 *
 * @param startaddr relevant pointer to start of user-data
 * @return see @brief
 */
static struct block_data *get_memblock_metadata(const mem *startaddr) {
    assert(is_aligned(startaddr, MAX_ALIGN));
    /* following arithmetic should match order of memory in new_block function.
     * in this case the block's metadata size is aligned to max alignment so it
     * may be further back in memory than just its sizeof() */
    return (struct block_data *)(startaddr - sizeof(struct block_data));
}

/**
 * @brief thread-safe: checks if current memory chunk has enough space
 * available, and allocates new chunk if not
 *
 * if enough memory is available in chunk at time of call, nothing is done and
 * current chunk is returned.
 * if not enough memory is available at time of call, this function locks a
 * mutex and adds an empty chunk to @module.
 *
 * in the time between when this
 * function is called and when it returns, enough space for @size_mem_needed is
 * guaranteed to have been available (at some point in that timespan). whether
 * enough memory is actually available after return depends on if other threads
 * consumed all available memory in that timespan.
 *
 * @param module module to add chunk to
 * @param chunk_size size of new chunk
 * @param size_mem_needed size of memory needed from the chunk
 * @return chunk that has enough space for @size_mem_needed at time of call, or
 * nullptr if malloc() fails
 */
static struct memchunk *_Nullable ondemand_newchunk(
    struct memblock_allocator *_Nonnull module, size_t chunk_size,
    size_t size_mem_needed) {

    struct memchunk *newchunk =
        atomic_load_explicit(&module->cur_chunk, memory_order_relaxed);

    if ( is_chunk_full(newchunk, size_mem_needed) ) {
        pthread_mutex_lock(&module->memchunk_lock);

        /* no need to atomically load here because of lock, and chunk
         * pointer is written to only under this lock */
        if ( is_chunk_full(module->cur_chunk, size_mem_needed) ) {
            /* this assignment has to be atomic in case some other thread
             * executes the atomic load above concurrently with the following
             * assignment */
            newchunk = new_memchunk(module->cur_chunk, chunk_size);
            if ( newchunk == nullptr ) {
                /* don't store newchunk, unlock mutex and return nullptr */
                goto fail_nomem;
            }
            atomic_store_explicit(&module->cur_chunk, newchunk,
                                  memory_order_relaxed);

            /* TODO: store remaining space of old chunk in block list after
             * assignment */
        }

    fail_nomem:
        pthread_mutex_unlock(&module->memchunk_lock);
    }

    return newchunk;
}

/* maybe return status ENOMEM instead of nullptr when out of memory? */
/**
 * @brief allocates a new block in chunk
 *
 * @param module module to allocate from
 * @param metadata pointer to variable to store new block pointer in, on return,
 * either a valid pointer is stored or function returns NOMEM
 * @param size size of block to allocate, must be > 0
 * @return NOMEM if new chunk is needed and can't be allocated,
 * MAX_SIZE_EXCEEDED if size is too big, MEM_SUCCESS on success */
[[nodiscard]] static mem_status_t
new_block(struct memblock_allocator *_Nonnull module,
          struct block_data **_Nonnull metadata, blk_size_t size) {
    assert(size > 0);
    struct block_data *block_metadata;
    struct memchunk   *chunk =
        atomic_load_explicit(&module->cur_chunk, memory_order_relaxed);

    /* round size to closest allowed size */
    const blk_size_t block_size = round_to_block(size);
    const blk_size_t total_size = sizeof(*block_metadata) + block_size;

    if ( total_size > chunk->total_size ) return MAX_SIZE_EXCEEDED;

    mem *oldtop;
    do {
        /* get current memory chunk if enough space is available, or allocate
         * and return new chunk if necessary */
        chunk = ondemand_newchunk(module, module->chunk_size, total_size);

        /* can't allocate more memory */
        if ( chunk == nullptr ) return NOMEM;

        /* allocate memory for new block, keep block metadata right behind
         * actual memory. align to struct block_data since that will be the
         * memory following the block itself (next block will struct block_data
         * first)*/
        oldtop = atomic_fetch_add_explicit(&chunk->top, total_size,
                                           memory_order_relaxed);

        /* if the following condition is true, the atomic instruction above
         * attempted to reserve space in chunk but there wasn't enough.
         * ondemand_newchunk() decides what to do with the remaining space. */
    } while ( oldtop + total_size > CHUNK_END_PTR(chunk) );

    /* logic check: make sure prev block end addr was aligned to fit struct
     * block_data */
    assert(is_aligned(oldtop, alignof(struct block_data)));
    /* logic check: make sure variables have legal values */
    assert(oldtop - chunk->startaddr >= 0 &&
           (size_t)(oldtop - chunk->startaddr) <= chunk->total_size);

    block_metadata = (struct block_data *)oldtop;
    init_block_data(block_metadata, block_size);

    *metadata = block_metadata;

    return MEM_SUCCESS;
}

void *_Nullable memblock_alloc(struct memblock_allocator *_Nonnull instance,
                               size_t size) {
    if ( size < 1 ) return nullptr;

    struct block_data *memblock = bucket_retrieve(instance, size);

    /* while loop since the last new_block call might return nullptr if chunk is
     * full. if chunk is full, try to alloc new chunk and try again. */
    if ( memblock == nullptr ) {
        mem_status_t status = new_block(instance, &memblock, size);

        switch ( status ) {
            case NOMEM:
                [[fallthrough]];

            case MAX_SIZE_EXCEEDED:
                return nullptr;

            case MEM_SUCCESS:
                assert(memblock != nullptr);
                break;

            default:
                /* unknown return value */
                assert(true); // NOLINT
        }
    }

    return (void *)get_memblock_startaddr(memblock);
}

void memblock_dealloc(struct memblock_allocator *_Nonnull instance,
                      void *_Nonnull block) {
    bucket_store(instance, get_memblock_metadata(block));
}
