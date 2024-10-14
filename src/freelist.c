#include "freelist.h"

#include <stdatomic.h>
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
    _Atomic list_index next_index;
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

/**
 * @brief returns ptr to index of next available empty slot after @head in free
 * list
 */
_Atomic list_index *get_next_empty(struct freelist *list, list_index head_idx) {
    return &((struct freelist_data *)list_elem(list, head_idx))->next_index;
}

freelist_status freelist_insert(struct freelist *list, void *elem) {
    atomic_bool        is_list_initialized = false;
    _Atomic list_index top = 0;
    _Atomic list_index head = list->array_len;
    _Atomic list_index nexthead = list->array_len;

    top++; // fetch_and_inc, reserve slot
    // reserve head - atomically head <- head.next and fetch headcopy
    // if headcopy is out of bounds(alias for top==head), head.next was invalid
    // (make sure always invalid in this scenario), use reserved slot if top is
    // in bounds. otherwise (top is out of bounds) list is full. if headcopy is
    // in bounds, use (reserved) headcopy. make sure head.next is invalid if
    // this is the last valid head

    // base idea:
    // atomically reserve top in case list was not fully initialized.
    // then, atomically reserve head (by atomically assigning head = head.next
    // and fetching) now free to take my time interacting with head - if in
    // bounds:

    // new idea:
    // base state: top = 0, head = arr_len (out of bounds)
    // if list not initialized:
    // atomic fetch and inc top
    // if top is in bounds, spot is free.
    // if top is out of bounds, list is initialized - set list initialized,
    // atomically dec and use head. even if many threads enter this branch when
    // the list is full, the out of bounds condition will always occur. if list
    // is initialized: atomically fetch exchange head = head.next if fetched
    // head is out of bounds, list is full if fetched head is in bounds, use
    // head

    if ( !is_list_initialized ) {
        list_index oldtop = atomic_fetch_add(&top, 1);
        if ( oldtop < list->array_len ) {
            // copy elem
            // reset oldtop = list->array_len
            return FREELIST_SUCCESS;
        }
        atomic_store(&is_list_initialized, true);
    }

    /* if list is full, next head is equal to array_len */
    list_index oldhead;
    do {
        oldhead = atomic_load(&head);
        nexthead = atomic_load(get_next_empty(list, oldhead));
    } while ( !atomic_compare_exchange_strong(&head, &oldhead, nexthead) );

    if ( oldhead >= list->array_len ) {
        return FREELIST_FULL;
    }

    // copy elem to oldhead

    return FREELIST_SUCCESS;
}

void freelist_rm(struct freelist *list, list_index idx) {
    struct freelist_data data = {.next_index = list->head};

    /* copy index of previous list element to new free slot */
    memcpy(list_elem(list, idx), &data, sizeof(data));

    list->head = idx;
}
