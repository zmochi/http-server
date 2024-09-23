#ifndef __LIST_H
#define __LIST_H

#include <src/container_of.h>

struct list_item {
    struct list_item *prev, *next;
};

#define list_entry(item_ptr, container_type, container_member)                 \
    container_of(item_ptr, container_type, container_member)

static inline void init_entry(struct list_item *entry) {
    entry->prev = entry;
    entry->next = entry;
}

/**
 * @brief Inserts a list item between two other list items
 *
 * @param new new item
 * @param prev item to be previous to new
 * @param next item to be next of new
 */
static inline void insert_entry(struct list_item *new, struct list_item *prev,
                                struct list_item *next) {
    new->next = next;
    new->prev = prev;
    prev->next = new;
    next->prev = new;
}

/**
 * @brief places @new before @entry
 *
 * @param new item to add
 * @param entry item that will be next of @new
 */
static inline void list_add_tail(struct list_item *new,
                                 struct list_item *entry) {
    insert_entry(new, entry->prev, entry);
}

/**
 * @brief places @new after @entry
 *
 * @param new item to add
 * @param entry item to be prev of @new
 */
static inline void list_add_head(struct list_item *new,
                                 struct list_item *entry) {
    insert_entry(new, entry, entry->next);
}

/**
 * @brief For internal use, deletes the consecutive chain of items between @prev
 * and @next (non-inclusive)
 *
 * @param prev start of chain to remove
 * @param next end of chain to remove
 */
static inline void _list_del(struct list_item *prev, struct list_item *next) {
    prev->next = next;
    next->prev = prev;
}

/**
 * @brief remove item from the list containing it
 * does nothing if item is not contained in a list (is a stand-alone item)
 *
 * @param entry entry to remove
 */
static inline void list_rm(struct list_item *entry) {
    _list_del(entry->prev, entry->next);
}

#endif /* __LIST_H */
