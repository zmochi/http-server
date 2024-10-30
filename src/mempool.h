#ifndef __MEMPOOL_H
#define __MEMPOOL_H

#include <src/defs.h>
#include <stddef.h> /* for size_t */

struct buffer {
    struct mempool *__nullable pool;
    char                      *buffer;
    /* current capacity and max capacity, respectively */
    size_t capacity, capacity_limit;
    /* how much of the buffer has been written to, may be used for other
     * purposes as well */
    size_t buflen;
};

struct mempool;
struct block_data;

typedef enum {
    MEM_SUCCESS,
    NOMEM,
    MAX_SIZE_EXCEEDED,
} mem_status_t;

/**
 * @brief reallocates buffer to new size, if not exceeding max_size
 *
 * @param buf ptr to buffer
 * @param bufsize ptr to capacity of buffer
 * @param max_size maximum demanded capacity of buffer
 * @param new_size capacity to reallocate to
 * @return 0 on success, -2 if new_size is exceeded
 */
int handler_buf_realloc(char **buf, size_t *bufcap, size_t max_size,
                        size_t new_size);

int initialize_mempool_module(void);

/**
 * @brief get a new memory pool
 *
 * @param parent parent pool or NULL if no parent should be assigned
 * @param size_hint total size of pool, if known ahead of time. if unknown, pass
 * 0
 */
struct mempool *new_mempool(struct mempool *__nullable parent);

int destroy_mempool(struct mempool *__nonnull mempool);

/**
 * @brief get new memory block from a pool
 *
 * @param mempool memory pool of block
 * @param size size of memory block
 */
void *mempool_alloc(struct mempool *__nonnull mempool, size_t size);

void init_buffer(struct buffer *buf, char *buffer, size_t capacity,
                 size_t capacity_limit);

mem_status_t new_dynamic_buffer(struct buffer *__nonnull   buffer,
                                struct mempool *__nullable pool,
                                size_t initial_size, size_t size_limit);

/* maybe write_buffer automatically resizes without returning? */
mem_status_t write_buffer(struct buffer *buffer, char *data, size_t size);

mem_status_t resize_buffer(struct buffer *__nonnull buffer, size_t new_size);

int free_buffer(struct buffer *__nonnull buffer);

#endif /* __MEMPOOL_H */
