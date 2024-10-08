/**
 * @file
 * @brief functions for managing a free list inside an array. The passed array
 */

#ifndef __FREELIST_H
#define __FREELIST_H

#include <stdatomic.h>
#include <stddef.h> /* for size_t */
#include <stdint.h> /* for uint32_t */

typedef uint32_t
    list_index; /* this data is inserted in empty places in the array,
               so it must be as small as possible. sizeof(list_index) determines
               the minimum size of elements in the freelist. if array length
               doesn't exceed 4GB this is a good trade-off */

/* for the union trick to work, list_index must be 32 bits */
static_assert(sizeof(list_index) == sizeof(uint32_t));
struct freelist {
    /* union to allow incrementing head and top together, atomically */
    union {
        _Atomic uint64_t head_top_union;
        struct {
            _Atomic list_index head;
            _Atomic list_index top;
        };
    };
    list_index array_len;
    size_t     elem_size;
    void      *array;
};

typedef enum {
    FREELIST_ARR_ELEM_TOO_SMALL, /* may only be returned from freelist_init() */
    FREELIST_FULL, /* may only be returned from freelist_insert() */
    FREELIST_ERR,
    FREELIST_SUCCESS,
} freelist_status;

freelist_status freelist_init(struct freelist *freelist, void *array,
                              list_index array_len, size_t elem_size);

/**
 * @brief inserts element into freelist
 *
 * @param list list to insert into
 * @param elem pointer to element to insert
 * @return FREELIST_FULL if list is full, FREELIST_ERR on error and
 * FREELIST_SUCCESS on success
 */
freelist_status freelist_insert(struct freelist *list, void *elem);

/**
 * @brief removes element at specified index from the freelist
 * it is the callers responsibility to ensure the array has an item in that
 * index. calling freelist_rm() on a free slot will probably break the list.
 *
 * @param list pointer to list to remove from
 * @param idx index of item to remove
 */
void freelist_rm(struct freelist *list, list_index idx);

/**
 * @brief returns ptr to element with index @idx in @list
 */
void *list_elem(struct freelist *list, list_index idx);
#endif /* __FREELIST_H */
