#include "freelist.h"

#include <_static_assert.h>
#include <stdio.h>  /* printf */
#include <string.h> /* for memcpy */

/* the list has a head value, pointing to the last free slot. each free slot has
 * a next_index value pointing to the next free slot. to avoid initializing the
 * entire array, the top value is used to indicate that the array is free from
 * that point forward. when the array has been filled once, top is assigned the
 * sentinel value of array_len which is invalid if there is no more free space,
 * head is assigned the sentinel value of top.
 */

/* content of a free slot */
struct freelist_data {
    list_index next_index;
};

freelist_status freelist_init(struct freelist *freelist, void *array,
                              list_index array_len, size_t elem_size) {
    if ( elem_size < sizeof(struct freelist_data) )
        return FREELIST_ARR_ELEM_TOO_SMALL;

    freelist->array_len = array_len;
    freelist->elem_size = elem_size;
    freelist->array = array;
    freelist->head = freelist->top = 0;

    return FREELIST_SUCCESS;
}

void *list_elem(struct freelist *list, list_index idx) {
    return (void *)((char *)list->array + (idx * list->elem_size));
}

void inc_head_top_atomic(struct freelist *list) {
    constexpr uint64_t inc = (1ULL << 32) + 1ULL;
    list->head_top_union += inc;
}

/**
 * @brief returns index of next available empty slot after @head in free list
 */
list_index get_next_empty(struct freelist *list) {
    return ((struct freelist_data *)list_elem(list, list->head))->next_index;
}

freelist_status freelist_insert(struct freelist *list, void *elem) {
    list_index head = list->head;
    list_index top = list->top;

    if ( head == top ) {
        if ( top >= list->array_len ) {
            /* no space left */
            return FREELIST_FULL;
        }

        /* list hasn't been fully initialized, there's un-initialized empty
         * space at @top */
        memcpy(list_elem(list, list->top), elem, list->elem_size);

        inc_head_top_atomic(list);
    } else {
        /* list is not full, head points at empty slot which contains pointer to
         * next free slot
         * if this is the last empty free slot then next_empty will be
         * array_len, out of bounds */
        list_index next_empty = get_next_empty(list);

        /* failsafe for invalid index */
        if ( !(next_empty < list->array_len) ) return FREELIST_ERR;

        memcpy(list_elem(list, head), elem, list->elem_size);
        list->head = next_empty;
    }

    return FREELIST_SUCCESS;
}

void freelist_rm(struct freelist *list, list_index idx) {
    struct freelist_data data = {.next_index = list->head};

    /* copy index of previous list element to new free slot */
    memcpy(list_elem(list, idx), &data, sizeof(data));

    list->head = idx;
}
