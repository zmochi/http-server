#include "list.h"
/* for NULL definition */
#include <stdlib.h>

#ifndef __QUEUE_H
#define __QUEUE_H

#define SUPPRESS_UNUSED(arg) ((void)(arg))

struct queue {
    struct list_item *head;
};

/**
 * @brief initializes a queue struct @queue (currently just a placeholder that
 * does nothing)
 *
 * @param queue queue to initialize
 * @return 0 on success, -1 on failure
 */
static inline int init_queue(struct queue *queue) {
    SUPPRESS_UNUSED(queue);
    return 0;
}

static inline int destroy_queue(struct queue *queue) {
    SUPPRESS_UNUSED(queue);
    return 0;
}

static inline bool is_empty(struct queue *queue) { return queue->head == NULL; }

static inline struct list_item *dequeue(struct queue *queue) {
    if ( is_empty(queue) ) return NULL;

    struct list_item *dequeued_entry = queue->head;
    queue->head = queue->head->prev;
    list_rm(dequeued_entry);

    if ( queue->head == dequeued_entry ) queue->head = NULL;

    return dequeued_entry;
}

static inline void enqueue(struct queue *queue, struct list_item *new) {
    if ( is_empty(queue) ) {
        init_entry(new);
        queue->head = new;
    } else {
        list_add_head(new, queue->head);
    }
}

static inline struct list_item *peek(struct queue *queue) {
    return queue->head;
}

#endif /* __QUEUE_H */
