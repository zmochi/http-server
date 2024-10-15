/**
 * @file freelist.c
 * @brief lock-free thread-safe free list implementation, for managing a
 * freelist inside an existing array.
 */

#include "freelist.h"

#include <stdatomic.h>
#include <string.h> /* for memcpy */

#ifdef DEBUG
#include <assert.h>
#define ASSERT_VALID_INDEX(list, idx)                                          \
    assert(0 <= (idx) && (idx) < (list)->array_len)
#else
#define NOOP                          (void)0
#define assert(cond)                  NOOP
#define ASSERT_VALID_INDEX(list, idx) NOOP
#endif

/* content of a free slot */
struct freelist_data {
    _Atomic fl_index next_index;
};

/* to be used in freelist.h, imported with `extern` */
const size_t fl_alignment = alignof(struct freelist_data);

fl_status do_freelist_init(struct freelist *freelist, void *array,
                           fl_index array_len, size_t elem_size) {
    freelist->array_len = array_len;
    freelist->elem_size = elem_size;
    freelist->array = array;
    freelist->head = array_len;
    freelist->top = 0;
    freelist->is_list_initialized = false;

    return FL_SUCCESS;
}

static fl_index calculate_index(struct freelist *list, void *elem) {
    if ( elem < list->array )
        return list->array_len; /* indicate error by returning array_len */
    fl_index idx = (fl_index)(((size_t)((char *)elem - (char *)list->array)) /
                              list->elem_size);
    ASSERT_VALID_INDEX(list, idx);

    return idx;
}

void *list_elem(struct freelist *list, fl_index idx) {
    ASSERT_VALID_INDEX(list, idx);
    return (void *)((char *)list->array + (idx * list->elem_size));
}

/**
 * @brief returns ptr to index of next available empty slot given in the array
 * element in @idx list
 */
static _Atomic fl_index *get_next_empty(struct freelist *list, fl_index idx) {
    ASSERT_VALID_INDEX(list, idx);
    return &((struct freelist_data *)list_elem(list, idx))->next_index;
}

void *freelist_alloc(struct freelist *list) {
    atomic_bool      *is_list_initialized = &list->is_list_initialized;
    _Atomic fl_index *top = &list->top;
    _Atomic fl_index *head = &list->head;

    // base state: top = 0, head = arr_len (out of bounds)
    //
    // if list not initialized:
    // atomic fetch and inc top, reserves potential slot
    // if top is in bounds, spot is free.
    // if top is out of bounds, list is initialized - set list initialized,
    // atomically dec and use head. even if many threads enter this branch when
    // the list is full, the out of bounds condition will always occur.
    //
    // if list is initialized: atomically fetch exchange head = head.next if
    // fetched head is out of bounds, list is full.
    // if fetched head is in bounds, use head

    if ( !(*is_list_initialized) ) {
        fl_index oldtop = atomic_fetch_add(top, 1);
        if ( oldtop < list->array_len ) {
            return list_elem(list, oldtop);
        }
        // reset oldtop = list->array_len
        atomic_store(is_list_initialized, true);
    }

    fl_index oldhead;
    fl_index nexthead;
    do {
        oldhead = atomic_load(head);
        /* can avoid this branch if list->head holds a pointer to slots in the
         * array, and the invalid element will be a special slot in the list
         * struct containing a pointer to itself, so each load to @nexthead will
         * preserve the value of @head on success */
        if ( oldhead >= list->array_len ) {
            return nullptr; /* return nullptr if list is full */
        }

        nexthead = atomic_load(get_next_empty(list, oldhead));
    } while ( !atomic_compare_exchange_strong(head, &oldhead, nexthead) );

    // copy elem to oldhead
    // index of new elem is still unknown while copying so no need for lock, to
    // protect against get() while copying

    return list_elem(list, oldhead);
}

void *freelist_insert(struct freelist *list, void *elem) {
    void *fl_slot = freelist_alloc(list);

    if ( fl_slot == nullptr ) return nullptr;

    memcpy(fl_slot, elem, list->elem_size);
    return fl_slot;
}

fl_status freelist_rm(struct freelist *list, void *elem) {
    fl_index idx = calculate_index(list, elem);
    ASSERT_VALID_INDEX(list, idx);
    if ( idx >= list->array_len ) return FL_ERR;

    struct freelist_data *data = (struct freelist_data *)(list_elem(list, idx));

    data->next_index = atomic_exchange(&list->head, idx);

    return FL_SUCCESS;
}
