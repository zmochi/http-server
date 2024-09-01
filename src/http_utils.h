#include "../libs/boost/CURRENT_FUNCTION.hpp"
#include "headers.h"
#include "main.h"

#ifndef __HTTP_UTILS_H
#define __HTTP_UTILS_H

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG(fmt, ...)                                                          \
    printf("LOG: %s: " fmt "\n", BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)                                                      \
    fprintf(stderr, "ERROR: %s: " fmt "\n", BOOST_CURRENT_FUNCTION,            \
            ##__VA_ARGS__)

#define HANDLE_ALLOC_FAIL()                                                    \
    {                                                                          \
        LOG_ERR("Allocation failed in function %s at line %d",                 \
                BOOST_CURRENT_FUNCTION, __LINE__);                             \
        exit(1);                                                               \
    }

/* returns size_t of statically allocated array */
#define ARR_SIZE(arr) ((size_t)(sizeof(arr) / sizeof(arr[0])))

ev_ssize_t copy_headers_to_buf(struct http_header *headers, size_t num_headers,
                               char *buffer, size_t capacity);

/**
 * @brief Loads entire contents of file specified by filepath into `buf`.
 *
 * @param buf Buffer to write to
 * @param buflen Maximum amount of space available in `buf`
 * @param filepath Path of file to write from
 * @return 0 on success, -1 on error, or the number of
 * bytes written to buffer if EOF was not reached.
 */
ev_ssize_t  load_file_to_buf(FILE *file, char *buf, size_t buflen,
                             size_t *last_len);
int         populate_headers_map(struct header_hashset *set,
                                 struct phr_header headers[], size_t num_headers);
int         http_extract_validate_header(struct header_hashset *set,
                                         const char            *header_name,
                                         size_t                 header_name_len,
                                         const char            *expected_value,
                                         size_t                 expected_value_len);
int         http_extract_content_length(struct header_hashset *set,
                                        size_t                *content_length_storage,
                                        size_t                 max_content_length);
int         handler_buf_realloc(char **buf, size_t *bufsize, size_t max_size,
                                ev_ssize_t new_size);
const char *stringify_statuscode(http_status_code status_code);
bool        is_integer(const char str[], int str_len);
ev_ssize_t  num_to_str(char *str, size_t strcap, size_t num);
int         strftime_gmtformat(char *buf, size_t buflen);
void        catchExcp(int condition, const char *err_msg, int action);

#endif /* __HTTP_UTILS_H */
