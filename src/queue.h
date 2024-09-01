#include "list.h"
/* for NULL definition */
#include <stdlib.h>

#ifndef __QUEUE_H
#define __QUEUE_H

struct queue {
    struct list_item *head;
};

static inline int is_empty(struct queue *queue) { return queue->head == NULL; }

static inline struct list_item *dequeue(struct queue *queue) {
    if ( is_empty(queue) ) return NULL;

    struct list_item *dequeued_entry = queue->head;
    queue->head                      = queue->head->prev;
    list_rm(dequeued_entry);

    return dequeued_entry;
}

static inline void enqueue(struct queue *queue, struct list_item *new) {
    if ( is_empty(queue) )
        queue->head = new;
    else
        list_add_head(new, queue->head);
}

static inline struct list_item *peek(struct queue *queue) {
    return queue->head;
}

#endif /* __QUEUE_H */
