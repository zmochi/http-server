#include "../libs/boost/CURRENT_FUNCTION.hpp"
#include "headers.h"

#include <event2/util.h>
#include <stdio.h>

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

/* exit() call should not be removed here, will break code */
#define LOGIC_ERR(err_fmt, ...)                                                \
    {                                                                          \
        LOG_ERR(err_fmt, ##__VA_ARGS__);                                       \
        exit(1);                                                               \
    }

#define _VALIDATE_LOGIC(logic_cnd, err_msg, ...)                               \
    if ( !(logic_cnd) ) LOGIC_ERR(err_msg, ##__VA_ARGS__);

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
ev_ssize_t load_file_to_buf(FILE *file, char *buf, size_t buflen,
                            size_t *last_len);
int        populate_headers_map(struct header_hashset *set,
                                struct http_header headers[], size_t num_headers);
int        http_extract_validate_header(struct header_hashset *set,
                                        const char            *header_name,
                                        size_t                 header_name_len,
                                        const char            *expected_value,
                                        size_t                 expected_value_len);
/**
 * @brief reallocates buffer to new size, if not exceeding max_size
 *
 * @param buf ptr to buffer
 * @param bufsize ptr to capacity of buffer
 * @param max_size maximum demanded capacity of buffer
 * @param new_size capacity to reallocate to
 * @return 0 on success, -2 if new_size is exceeded
 */
int  handler_buf_realloc(char **buf, size_t *bufsize, size_t max_size,
                         ev_ssize_t new_size);
bool is_integer(const char str[], int str_len);

/**
 * @brief converts a non-negative size_t variable to a string (e.g 100 -> "100")
 * adds a null byte at end of string
 *
 * @param str buffer to place the result in
 * @param strcap capacity of buffer
 * @param num num to stringify
 * @return on success, number of characters written to @str, not including null
 * byte. -1 on failure
 */
ev_ssize_t num_to_str(char *str, size_t strcap, size_t num);

/**
 * @brief returns the numeric value of a string.
 *
 * @param str string containing the number to convert
 * @param strlen length of string to convert, must be > 0
 * @return the numeric value of the string, or -1 if can't be converted
 */
ev_ssize_t str_to_positive_num(const char *str, size_t strlen);
int        strftime_gmtformat(char *buf, size_t buflen);
void       catchExcp(int condition, const char *err_msg, int action);

#endif /* __HTTP_UTILS_H */
