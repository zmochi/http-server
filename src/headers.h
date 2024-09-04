#include "http_limits.h"

#ifndef __HEADERS_H
#define __HEADERS_H

#include "../libs/picohttpparser/picohttpparser.h"
#include <stdbool.h>

struct http_header {
    /* this union allows accessing the fields of struct phr_header as if they
     * were native to struct http_header */
    union {
        struct phr_header phr_header;
        struct {
            const char *name;
            size_t      name_len;
            const char *value;
            size_t      value_len;
        };
    };
};

struct header_value {
    char *value;
    int   value_len;
};

enum http_header_props {
    MAX_NUM_HEADERS          = 100,
    HEADER_VALUE_VALID       = 2,
    HEADER_EXISTS            = 4,
    HEADER_VALUE_EXCEEDS_MAX = 8,
};

/* a hashset to be used as a blackbox with the function defined in headers.h */
struct header_hashset;

static inline void http_header_init(struct http_header *header,
                                    const char         *header_name,
                                    const char         *header_value) {
    header->name  = header_name;
    header->value = header_value;
}

struct header_hashset *malloc_init_hashset(void);
void                   reset_header_hashset(struct header_hashset *set);
void                   free_header_hashset(struct header_hashset *set);
struct header_value   *http_get_header(struct header_hashset *set,
                                       const char *name, int name_len);
int http_set_header(struct header_hashset *set, const char *name, int name_len,
                    const char *value, int value_len);

#endif /* __HEADERS_H */
