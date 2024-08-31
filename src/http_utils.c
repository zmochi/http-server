#include "http_utils.h"
#include "headers.h"

#include <stdlib.h>
#include <string.h>

extern const int BACKLOG;

/**
 * @brief gets current GMT time in the format (example) "Sun, 01 Jan 1970
 * 00:00:00 GMT"
 *
 * @param buf buf to fill time in
 * @param bufcap capacity of @buf
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int strftime_gmtformat(char *buf, size_t bufcap) {

    time_t     time_now         = time(NULL);
    struct tm *tm_info          = gmtime(&time_now);
    int        EXPECTED_FMT_LEN = 29;

    /* strftime returns number of characters written to buf on success. The
     * format passed should always yield EXPECTED_FMT_LEN characters */
    if ( strftime(buf, bufcap, "%a, %d %b %Y %H:%M:%S GMT", tm_info) !=
         EXPECTED_FMT_LEN )
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
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
                               char *buffer, size_t capacity) {
    const int NO_MEM_ERR    = -1;
    size_t    bytes_written = 0;
    /* the buffer start point and buffer capacity change while writing to the
     * buffer. these variables hold the effective buffer and its effective
     * capacity */
    size_t eff_bufcap;
    char  *eff_buf;
    int    ret;

    static const char *HEADER_FMT = "%s: %s\r\n";

    for ( size_t i = 0; i < num_headers; i++ ) {
        struct http_header header = headers[i];
        eff_bufcap                = capacity - bytes_written;
        eff_buf                   = buffer + bytes_written;

        /* snprintf should be fine since HTTP standard disallows null bytes in
         * header values */
        ret = snprintf(eff_buf, eff_bufcap, HEADER_FMT, header.header_name,
                       header.header_value);

        if ( ret > eff_bufcap ) { // out of memory, capacity too small
            return NO_MEM_ERR;
        } else if ( ret < 0 ) {
            LOG_ERR("snprintf: headers: %s", strerror(errno));
            exit(1);
        }

        bytes_written += ret;
    }

    return bytes_written;
}

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
ev_ssize_t load_file_to_buf(FILE *file, char *restrict buf, size_t buf_capacity,
                            size_t *total_read) {
    const int FILE_FAIL = -2, FILE_EOF = -1;
    /* would prefer to mmap() file into memory but not cross-compatible that
     * way... */
    size_t     ret_size_t, capacity = buf_capacity, last = *total_read;
    ev_ssize_t ret;

    /* read fread return value into an appropriate type: */
    ret_size_t = fread(buf + last, sizeof(char), capacity - last, file);
    if ( ret_size_t > EV_SSIZE_MAX ) {
        LOG_ERR("fread: file contains more data than ssize_t can handle");
        exit(1);
    }
    /* return value of fread fits in ssize_t, cast it: */
    ret = ret_size_t;

    if ( ret < capacity - last ) {
        if ( ferror(file) ) {
            LOG_ERR("fread: %s", strerror(errno));
            return FILE_FAIL;
        } else if ( feof(file) ) {
            /* reached EOF */
            *total_read += ret;
            return FILE_EOF;
        } else {
            LOG_ERR("unknown error");
            exit(1);
        }
    }

    /* haven't reached EOF, caller must increase buffer capacity */
    *total_read += ret;
    return ret;
}

int populate_headers_map(struct header_hashset *set,
                         struct phr_header headers[], size_t num_headers) {

    for ( int i = 0; i < num_headers; i++ ) {
        struct phr_header header = headers[i];
        http_set_header(set, header.name, header.name_len, header.value,
                        header.value_len);
    }
    return 0;
}

int http_extract_validate_header(struct header_hashset *set,
                                 const char *restrict header_name,
                                 size_t header_name_len,
                                 const char *restrict expected_value,
                                 size_t expected_value_len) {
    short header_flags = 0;
    int   header_value_len;
    char *header_value =
        http_get_header(set, header_name, header_name_len, &header_value_len);

    if ( header_value_len != 0 ) {
        header_flags |= HEADER_EXISTS;

#define MIN(a, b) ((a < b) ? a : b)
        /* compare against expected value if needed: */
        if ( expected_value != NULL &&
             strncmp(header_value, expected_value,
                     MIN(expected_value_len, header_value_len)) == 0 ) {
            header_flags |= HEADER_VALUE_VALID;
        }
    }

    return header_flags;
}

int http_extract_content_length(struct header_hashset *set,
                                size_t                *content_length_storage,
                                size_t                 max_content_length) {

    short header_flags = 0;
    int   content_len_strlen;
    char *content_len_str = http_get_header(
        set, "Content-Length", strlen("Content-Length"), &content_len_strlen);

    if ( content_len_strlen == 0 ) {
        return header_flags;
    }

    header_flags |= HEADER_EXISTS;

    if ( !is_integer(content_len_str, content_len_strlen) ) {
        return header_flags;
    }

    // set null byte at end of string for call to `strtoumax`:
    *(content_len_str + content_len_strlen + 1) = '\x00';

    uintmax_t content_length = strtoumax(content_len_str, NULL, 10);

    if ( content_length > max_content_length ) {
        header_flags |= HEADER_VALUE_EXCEEDS_MAX;
    } else {
        header_flags |= HEADER_VALUE_VALID;
    }

    *content_length_storage =
        (size_t)content_length; // TODO: check if this cast is valid

    return header_flags;
}

int handler_buf_realloc(char **buf, size_t *bufsize, size_t max_size,
                        ev_ssize_t new_size) {
    // instead of realloc we can use a deamortized buffer (which
    // requires 3x space allocation)

    if ( *bufsize >= max_size ) {
        return MAX_BUF_SIZE_EXCEEDED;
    }
    *buf     = realloc(*buf, new_size);
    *bufsize = new_size;
    if ( *buf == NULL ) {
        // TODO
        exit(1);
    }

    return 0;
}

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
ev_ssize_t num_to_str(char *str, size_t strcap, size_t num) {
    ev_ssize_t ret;

    if ( (ret = snprintf(str, strcap, "%zu", num)) >= strcap ) {
        return -1;
    }

    return ret;
}

/**
 * @brief checks if a string of length str_len contains integer characters only
 *
 * @param str string to check against
 * @param str_len length of @str
 * @return false on failure, true on success
 */
inline bool is_integer(const char str[], int str_len) {
    for ( int i = 0; i < str_len; i++ ) {
        char ch = str[i];
        if ( ch < '0' || ch > '9' ) {
            return false;
        }
    }

    return true;
}

/** check if a function that returned `status` threw an error (Meaning it
returned `bad_status`)
 * @param status The actual value to check against.
 * @param bad_status `status` that triggers program to exit on failure.
 * @param err_msg Error message, prints to `stderr`.
 * @param bool_exit Whether to exit the program at failure.
*/
void catchExcp(int condition, const char *restrict err_msg, int action) {
    if ( condition ) {
        fprintf(stderr, "%s\n", err_msg);
        switch ( action ) {
            case 1:
                exit(1);
        }
    }
}
