#include <src/headers.h>
#include <src/http_limits.h>
#include <src/http_utils.h>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

int strftime_gmtformat(char *buf, size_t bufcap) {

    time_t       time_now = time(NULL);
    struct tm   *tm_info = gmtime(&time_now);
    unsigned int EXPECTED_FMT_LEN = 29;

    /* strftime returns number of characters written to buf on success. The
     * format passed should always yield EXPECTED_FMT_LEN characters */
    if ( strftime(buf, bufcap, "%a, %d %b %Y %H:%M:%S GMT", tm_info) !=
         EXPECTED_FMT_LEN )
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

ev_ssize_t copy_headers_to_buf(struct http_header *headers, size_t num_headers,
                               char *buffer, size_t capacity) {
    /* temporary fix to make arithmetic between @capacity and @bytes_written
     * legal */
    if ( capacity > EV_SSIZE_MAX )
        LOG_ABORT("Massive capacity reached, aborting");
    const int  NO_MEM_ERR = -1;
    ev_ssize_t bytes_written = 0;
    /* the buffer start point and buffer capacity change while writing to the
     * buffer. these variables hold the effective buffer and its effective
     * capacity */
    ev_ssize_t eff_bufcap;
    char      *eff_buf;
    int        ret;

    static const char *HEADER_FMT = "%s: %s\r\n";

    for ( size_t i = 0; i < num_headers; i++ ) {
        struct http_header header = headers[i];
        eff_bufcap = (ev_ssize_t)capacity - bytes_written;
        eff_buf = buffer + bytes_written;

        /* snprintf should be fine since HTTP standard disallows null bytes in
         * header values */
        ret = snprintf(eff_buf, eff_bufcap, HEADER_FMT, header.name,
                       header.value);

        if ( ret < 0 ) {
            LOG_ABORT("snprintf: headers: %s", strerror(errno));
        } else if ( ret > eff_bufcap ) { // out of memory, capacity too small
            return NO_MEM_ERR;
        }

        bytes_written += ret;
    }

    return bytes_written;
}

ev_ssize_t load_file_to_buf(FILE *file, char *restrict buf, size_t buf_capacity,
                            size_t *total_read) {
    const int FILE_FAIL = -2, FILE_EOF = -1;
    /* would prefer to mmap() file into memory but not cross-compatible that
     * way... */
    size_t ret, capacity = buf_capacity, last = *total_read;

    /* read fread return value into an appropriate type: */
    ret = fread(buf + last, sizeof(char), capacity - last, file);

    /* make sure it's safe to cast ret in return statement */
    if ( ret > EV_SSIZE_MAX ) {
        LOG_ERR("fread: file contains more data than ssize_t can handle");
        return FILE_FAIL;
    }

    /* not everything was read */
    if ( ret < capacity - last ) {
        if ( ferror(file) ) {
            LOG_ERR("fread: %s", strerror(errno));
            return FILE_FAIL;
        } else if ( feof(file) ) {
            /* reached EOF */
            *total_read += ret;
            return FILE_EOF;
        } else {
            LOG_ABORT("unknown error");
        }
    }

    /* haven't reached EOF, caller must increase buffer capacity */
    *total_read += ret;

    /* if statement above makes sure this cast is legal */
    return (ev_ssize_t)ret;
}

int populate_headers_map(struct header_hashset *set,
                         struct http_header headers[], size_t num_headers) {

    for ( unsigned int i = 0; i < num_headers; i++ ) {
        struct http_header header = headers[i];
        http_set_header(set, header.name, header.name_len, header.value,
                        header.value_len);
    }
    return 0;
}

enum http_header_props http_extract_validate_header(
    struct header_hashset *set, const char *restrict header_name,
    unsigned int           header_name_len, const char *restrict expected_value,
    unsigned int           expected_value_len) {
    enum http_header_props header_flags = 0;

    struct header_value *header_value =
        http_get_header(set, header_name, header_name_len);
    if ( header_value == NULL ) return header_flags;

    char        *header_value_buf = header_value->value;
    unsigned int header_value_len = header_value->value_len;

    if ( header_value_len != 0 ) {
        header_flags |= HEADER_EXISTS;

#define MIN(a, b) ((a < b) ? a : b)
        /* compare against expected value if needed: */
        if ( expected_value != NULL &&
             strncmp(header_value_buf, expected_value,
                     MIN(expected_value_len, header_value_len)) == 0 ) {
            header_flags |= HEADER_VALUE_VALID;
        }
    }

    return header_flags;
}

int handler_buf_realloc(char **buf, size_t *bufcap, size_t max_size,
                        size_t new_size) {
    // instead of realloc we can use a deamortized buffer (which
    // requires 3x space allocation)

    if ( new_size >= max_size ) return -2;

    *buf = realloc(*buf, new_size);
    *bufcap = new_size;

    if ( *buf == NULL ) HANDLE_ALLOC_FAIL();

    return 0;
}

ev_ssize_t num_to_str(char *str, size_t strcap, size_t num) {
    ev_ssize_t ret;
    ret = snprintf(str, strcap, "%zu", num);

    if ( ret < 0 || (size_t)ret >= strcap ) return -1;

    return ret;
}

ev_ssize_t str_to_positive_num(const char *str, size_t strlen) {

    /* +1 for null byte */
    size_t local_strlen = strlen + 1;
    char   local_str[local_strlen];
    char  *endptr;

    /* copy content_len into null terminated string to avoid surprises with
     * strtoumax, which expects a null terminated string */
    memcpy(local_str, str, strlen);
    /* terminate str with null */
    local_str[ARR_SIZE(local_str) - 1] = '\x00';

    uintmax_t content_length = strtoumax(local_str, &endptr, 10);

    if ( (ev_ssize_t)content_length < 0 ) return -1; // overflow

    // TODO: verify this is not dumb
    if ( *endptr != '\x00' ) return -1;

    return (ev_ssize_t)content_length;
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
