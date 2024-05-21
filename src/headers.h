#include "main.h"

#ifndef __HEADERS_H
#define __HEADERS_H

struct hash_header {
    char              *name;
    struct phr_header *req_header;
};

struct hash_header *http_get_header(const char *str, size_t len);
static unsigned int http_hash_header(const char *str, size_t len);
int                 http_set_header(const char *name, size_t name_len,
                                    struct phr_header *req_header);
#endif /* __HEADERS_H */
