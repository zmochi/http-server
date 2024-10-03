#include <libs/boost/CURRENT_FUNCTION.hpp>
#include <src/headers.h>

#include <event2/util.h> /* for ev_ssize_t */
#include <math.h>        /* for log10 in NUM_DIGITS macro */
#include <stdio.h>

#ifndef __HTTP_UTILS_H
#define __HTTP_UTILS_H

#ifdef DEBUG

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG_DEBUG(fmt, ...)                                                    \
    printf("DEBUG: %s: " fmt "\n", BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)

#define LOG_ERR_DEBUG(fmt, ...)                                                \
    (void)fprintf(stderr, "DEBUG: ERROR: %s: " fmt "\n",                       \
                  BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)
#else

#define LOG_DEBUG(fmt, ...)     ((void)0)
#define LOG_ERR_DEBUG(fmt, ...) ((void)0)

#endif

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG(fmt, ...)                                                          \
    printf("LOG: %s: " fmt "\n", BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)

#define LOG_ERR(fmt, ...)                                                      \
    (void)fprintf(stderr, "ERROR: %s: line %d: " fmt "\n",                     \
                  BOOST_CURRENT_FUNCTION, __LINE__, ##__VA_ARGS__)

#define LOG_ABORT(fmt, ...)                                                    \
    do {                                                                       \
        LOG_ERR(fmt, ##__VA_ARGS__);                                           \
        exit(1);                                                               \
    } while ( 0 )

#define HANDLE_ALLOC_FAIL()                                                    \
    do {                                                                       \
        LOG_ABORT("Allocation failed at line %d", __LINE__);                   \
    } while ( 0 )

/* exit() call should not be removed here, will break code */
#define LOGIC_ERR(err_fmt, ...)                                                \
    do {                                                                       \
        LOG_ERR(err_fmt, ##__VA_ARGS__);                                       \
        exit(1);                                                               \
    } while ( 0 )

#define _VALIDATE_LOGIC(logic_cnd, err_msg, ...)                               \
    do {                                                                       \
        if ( !(logic_cnd) ) LOGIC_ERR(err_msg, ##__VA_ARGS__);                 \
    } while ( 0 )

/* returns size_t of statically allocated array */
#define ARR_SIZE(arr) ((size_t)(sizeof(arr) / sizeof(arr[0])))

/* suppress unused argument warning */
#define SUPPRESS_UNUSED(arg) ((void)arg)

/* get number of digits in integer num */
static inline unsigned int NUM_DIGITS(size_t num) {
    return ((unsigned int)(log10((double)num) + 1));
}

/**
 * @brief copies and formats an array of headers into a buffer
 *
 * @param headers array of headers
 * @param num_headers number of elements in headers array
 * @param buffer buffer to copy formatted headers to
 * @param capacity buffer capacity
 * @return number of bytes written on success, -1 if capacity is too small
 */
ev_ssize_t copy_headers_to_buf(struct http_header *headers, size_t num_headers,
                               char *buffer, size_t capacity);

/**
 * @brief reads from @file to @buf with capacity @buf_capacity.
 *
 * caller should repeatedly call this function until EOF is reached, increasing
 * buffer capacity on each call where EOF wasn't reached.
 *
 * @param file open file to read from, opened with fopen()
 * @param buf buffer to load file contents into
 * @param buf_capacity buffer capacity
 * @param total_read total size read from file by the function so far. should be
 * 0 on first call and passed to the function unchanged on every following call.
 * @return number of bytes written in this call to the function, -1 on EOF, or
 * -2 if an error occurred
 */
ev_ssize_t load_file_to_buf(FILE *file, char *buf, size_t buflen,
                            size_t *last_len);

/**
 * @brief utility function to populate a `struct header_hashset` given a filled
 * array of `struct http_header`s
 *
 * currently does not provide an indication as to whether all HTTP header names
 * exist or not, simply ignores those cases (and doesn't populate the hashset
 * with invalid names)
 *
 * @param set `struct header_hashset` to populate
 * @param headers headers array filled with values to populate set from
 * @param num_headers number of entries in headers array
 * @return 0 on success, -1 on failure (currently there is no fail scenario
 * since invalid header names are ignored)
 */
int populate_headers_map(struct header_hashset *set,
                         struct http_header headers[], size_t num_headers);
/**
 * @brief gets header with the given name from header hashset @set and matches
 * its value against @expected_value.
 *
 * @param set hashset to extract header from
 * @param header_name header's name
 * @param header_name_len header's name length
 * @param expected_value expected value to match against
 * @param expected_value_len expected value length
 * @return a bitmask of fields from `enum http_header_props` (from headers.h)
 */
enum http_header_props http_extract_validate_header(
    struct header_hashset *set, const char *header_name,
    unsigned int header_name_len, const char *expected_value,
    unsigned int expected_value_len);
/**
 * @brief reallocates buffer to new size, if not exceeding max_size
 *
 * @param buf ptr to buffer
 * @param bufsize ptr to capacity of buffer
 * @param max_size maximum demanded capacity of buffer
 * @param new_size capacity to reallocate to
 * @return 0 on success, -2 if new_size is exceeded
 */
int handler_buf_realloc(char **buf, size_t *bufsize, size_t max_size,
                        size_t new_size);

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

/**
 * @brief gets current GMT time in the format (example) "Sun, 01 Jan 1970
 * 00:00:00 GMT"
 *
 * @param buf buf to fill time in
 * @param bufcap capacity of @buf
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int strftime_gmtformat(char *buf, size_t buflen);

void catchExcp(int condition, const char *err_msg, int action);

#endif /* __HTTP_UTILS_H */
