/**
 * @file freelist.c
 * @brief lock-free thread-safe free list implementation which does not require
 * initialization, for managing a freelist inside an existing array.
 */

#include "freelist.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h> /* for uint{64,32}_t */
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

/* content of a free slot: */
struct freelist_data {
    _Atomic fl_index next_index;
};

/* struct union_head_tag defined to solve ABA problem in freelist_alloc CAS loop
 */
static_assert(sizeof(fl_index) == sizeof(uint32_t),
              "bad freelist index, will break ABA union solution");
static_assert(
    sizeof(struct union_head_tag) == sizeof(_Atomic uint64_t),
    "bad size of struct union_head_tag, will break ABA union solution");

/* functions for writing to high and low 32 bits of a 64 bit value. head is the
 * current head value and tag is the number of times the head value was changed.
 * this is necessary to prevent the ABA problem. whether head/tag is the
 * high/low 32 bits of the 64 value is decided by the compiler, I guess */

static void write_tag(uint64_t *union_head_tag, const fl_index tag) {
    ((struct union_head_tag *)union_head_tag)->tag = tag;
}

static void write_head(uint64_t *union_head_tag, const fl_index head) {
    ((struct union_head_tag *)union_head_tag)->head = head;
}

static fl_index read_tag(const uint64_t *union_head_tag) {
    return ((struct union_head_tag *)union_head_tag)->tag;
}

static fl_index read_head(const uint64_t *union_head_tag) {
    return ((struct union_head_tag *)union_head_tag)->head;
}

/* to be used in freelist.h, imported with `extern` */
const size_t fl_alignment = alignof(struct freelist_data);

fl_status do_freelist_init(struct freelist *freelist, void *array,
                           fl_index array_len, size_t elem_size) {
    uint64_t init_union_head_tag;
    write_tag(&init_union_head_tag, 0);
    write_head(&init_union_head_tag, array_len);

    freelist->array_len = array_len;
    freelist->elem_size = elem_size;
    freelist->array = array;
    freelist->union_head_tag.union_head_tag = init_union_head_tag;
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
    _Atomic uint64_t *union_head_tag = &list->union_head_tag.union_head_tag;

    if ( !(*is_list_initialized) ) {
        fl_index oldtop = atomic_fetch_add(top, 1);
        if ( oldtop < list->array_len ) {
            return list_elem(list, oldtop);
        }
        // reset oldtop = list->array_len?
        atomic_store(is_list_initialized, true);
    }

    uint64_t old_head_tag;
    uint64_t new_head_tag;
    do {
        old_head_tag = atomic_load(union_head_tag);
        /* can avoid this branch if list->head holds a pointer to slots in
         * the array, and the invalid element will be a special slot in the
         * list struct containing a pointer to itself, so each load to
         * @nexthead will preserve the value of @head on success */
        if ( read_head(&old_head_tag) >= list->array_len ) {
            return nullptr; /* return nullptr if list is full */
        }

        write_head(&new_head_tag,
                   atomic_load(get_next_empty(list, read_head(&old_head_tag))));

        /* if the increment overflows the tag it should be fine, if overflow is
         * reached it's pretty much certain there are no other threads holding
         * on to very small old tags at the same time */
        write_tag(&new_head_tag, read_tag(&old_head_tag) + 1);
    } while ( !atomic_compare_exchange_strong(union_head_tag, &old_head_tag,
                                              new_head_tag) );

    return list_elem(list, read_head(&old_head_tag));
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

    data->next_index = atomic_exchange(&list->union_head_tag.head, idx);

    return FL_SUCCESS;
}
