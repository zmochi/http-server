
#ifndef __FREELIST_H
#define __FREELIST_H

#include <stdalign.h>  /* for alignof() */
#include <stdatomic.h> /* atomics */
#include <stddef.h>    /* for size_t */
#include <stdint.h>    /* for uint32_t */

typedef uint32_t
    fl_index; /* this data is inserted in empty places in the array,
               so it must be as small as possible. sizeof(list_index) determines
               the minimum size of elements in the fl. if array length
               doesn't exceed 4GB this is a good trade-off */
struct union_head_tag {
    union {
        _Atomic uint64_t union_head_tag;
        struct {
            _Atomic fl_index head;
            _Atomic fl_index tag;
        };
    };
};

struct freelist {
    atomic_bool           is_list_initialized;
    struct union_head_tag union_head_tag;
    _Atomic fl_index      top;
    fl_index              array_len;
    size_t                elem_size;
    void                 *array;
};

typedef enum {
    FL_FULL,
    FL_ERR,
    FL_SUCCESS,
} fl_status;

fl_status do_freelist_init(struct freelist *freelist, void *array,
                           fl_index array_len, size_t elem_size);

/* stringify macros for __LINE__ in fl_debug_info */
#define FL_DO_STRINGIFY(a) #a
#define FL_STRINGIFY(a)    FL_DO_STRINGIFY(a)

#define fl_debug_info "file " __FILE__ ", line " FL_STRINGIFY(__LINE__) ": "

/* defined in freelist.c */
extern const size_t fl_alignment;

/* convenience macro for initializing array of statically known type, making
 * sure size is correct and alignment is correct */
#define freelist_init(struct_fl_ptr, array, array_len)                         \
    do {                                                                       \
        static_assert(alignof(typeof((array)[0])) >= fl_alignment,             \
                      fl_debug_info                                            \
                      "bad alignment of user-supplied fl array");              \
        static_assert(sizeof((array)[0]) >= sizeof(struct freelist_data),      \
                      fl_debug_info "size of array element too smaller");      \
        do_freelist_init(struct_fl_ptr, (void *)(array), array_len,            \
                         sizeof((array)[0]));                                  \
    } while ( 0 )

/**
 * @brief allocates a freelist (array) slot.
 *
 * @param list list to allocate from
 * @return pointer to allocated slot of size list->elem_size
 */
void *freelist_alloc(struct freelist *list);

/**
 * @brief inserts element into freelist
 *
 * @param list list to insert into
 * @param elem pointer to element to insert, copies element into list
 * @return pointer to copy of elem inside the list, of size list->elem_size
 */
void *freelist_insert(struct freelist *list, void *elem);

/**
 * @brief removes element at specified index from the fl
 * it is the callers responsibility to ensure the array has an item in that
 * index. calling freelist_rm() on a free slot will probably break the list.
 *
 * @param list pointer to list to remove from
 * @param elem pointer to element in the list to remove
 * @return FL_SUCCESS on success, FL_ERR if elem has a bad address
 */
fl_status freelist_rm(struct freelist *list, void *elem);

/**
 * @brief returns ptr to element with index @idx in @list
 */
void *list_elem(struct freelist *list, fl_index idx);

#endif /* __FREELIST_H */
