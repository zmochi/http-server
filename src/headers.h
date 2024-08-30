#include "http_limits.h"

#ifndef __HEADERS_H
#define __HEADERS_H

#include "../libs/picohttpparser/picohttpparser.h"
#include <stdbool.h>
#include <stdlib.h>

struct http_header {
    /* this union allows accessing the fields of struct phr_header as if they
     * were native to struct http_header */
    union {
        struct phr_header phr_header;
        struct {
            const char *header_name;
            size_t      name_len;
            const char *header_value;
            size_t      value_len;
        };
    };
    struct http_header *next;
};

struct header_value {
    char *value;
    int   value_len;
};

/* a hashset to be used as a blackbox with the function defined in headers.h */
struct hashset {
    /* a buffer containing all header values, pointed to by elements in @arr */
    char value_storage[REQ_HEADER_VALUES_MAX_SIZE];
    /* an array containing pointers to the value of each header. the value is
     * stored in @value_storage */
    struct header_value *arr;
    /* pointer to where in value_storage values can be inserted */
    char *value_storage_ptr;
};

struct hashset *malloc_init_hashset(void);
char *http_get_header(struct hashset *set, const char *name, int name_len,
                      int *value_ptr);
int   http_set_header(struct hashset *set, const char *name, int name_len,
                      const char *value, int value_len);

#endif /* __HEADERS_H */
