#include "list.h"
/* for NULL definition */
#include <stdlib.h>

#ifndef __QUEUE_H
#define __QUEUE_H

struct queue {
    struct list_item  sentinel;
    struct list_item *head;
};

static inline void init_queue(struct queue *queue) {
    queue->head          = &queue->sentinel;
    queue->sentinel.next = &queue->sentinel;
    queue->sentinel.prev = &queue->sentinel;
}

static inline struct list_item *dequeue(struct queue *queue) {
    struct list_item *dequeued_entry = queue->head;
    queue->head                      = queue->head->prev;
    list_rm(dequeued_entry);

    return dequeued_entry;
}

static inline void enqueue(struct queue *queue, struct list_item *new) {
    list_add_head(new, queue->head);
}

static inline struct list_item *peek(struct queue *queue) {
    return queue->head;
}

static inline int is_empty(struct queue *queue) {
    return queue->head == &queue->sentinel;
}

#endif /* __QUEUE_H */
