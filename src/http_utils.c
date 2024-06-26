#include "http_utils.h"
#include "headers.h"
#include "status_codes.h"

int strftime_gmtformat(char *buf, size_t buflen) {

    time_t     time_now = time(NULL);
    struct tm *tm_info  = gmtime(&time_now);

    return strftime(buf, buflen, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
}

const char *stringify_statuscode(http_status_code status_code) {
    return status_codes.storage[status_code - status_codes.smallest_code];
}

// TODO: writing buflen - last_len size is too much, need to get size with fseek
int load_file_to_buf(char *buf, size_t buflen, size_t *bytes_written,
                     const char *filepath, size_t last_len) {
    FILE  *message_file = fopen(filepath, "r");
    size_t ret;
    size_t message_file_size;

    if ( !message_file ) {
        fprintf(stderr, "load_file_to_buf: couldn't open file at path %s",
                filepath);
        return -1;
    }

    fseek(message_file, 0, SEEK_END);
    message_file_size = ftell(message_file);
    ret               = fseek(message_file, last_len, SEEK_SET);

    if ( ret != 0 ) {
        return -1;
    }

    ret = fread(buf + last_len, 1, buflen - last_len, message_file);

    if ( ret <= 0 ) {
        if ( ferror(message_file) ) {
            return -1;
        } else if ( feof(message_file) ) {
            *bytes_written += ret;
            return 0; // success - reached eof
        }
    }

    // haven't reached EOF
    *bytes_written += ret;
    return ret;
}

int populate_headers_map(struct client_data *con_data) {
    struct phr_header *headers     = con_data->request->headers;
    size_t             num_headers = con_data->request->num_headers;

    for ( int i = 0; i < con_data->request->num_headers; i++ ) {
        struct hash_header *header =
            http_get_header(headers[i].name, headers[i].name_len);

        // TODO: make portable and fix logic (header would probably never be
        // null)
        // Assuming 2's complement, where -0 == 0 in bit presentation and
        // 0xFFFF.. represents -1, and assuming sign extended bitshift.
        header->req_header =
            (struct phr_header *)((intptr_t)&headers[i] *
                                  (-(-((intptr_t)header) >>
                                     (sizeof(intptr_t) * CHAR_BIT - 1))));
        // this is the branchless version of:
        // if ( header != NULL ) { // Recognized header
        //     header->req_header = &headers[i];
        // } else {
        //     header->req_header = NULL;
        // }
    }
    return 0;
}

int http_extract_validate_header(const char *restrict header_name,
                                 size_t header_name_len,
                                 char *restrict expected_value,
                                 size_t expected_value_len) {
    short              header_flags = 0;
    struct phr_header *header =
        http_get_header(header_name, header_name_len)->req_header;

    if ( header != NULL ) {
        header_flags |= HEADER_EXISTS;
        if ( strncmp(header->value, expected_value, expected_value_len) ) {
            header_flags |= (HEADER_VALUE_VALID);
        }
    }

    return header_flags;
}

int http_extract_content_length(size_t *content_length_storage,
                                size_t  max_content_length) {

    // check if we already got the content length
    if ( content_length_storage != 0 ) {
        return HEADER_EXISTS | HEADER_VALUE_VALID;
    }

    short              header_flags = 0;
    struct phr_header *header_content_len =
        http_get_header("Content-Length", strlen("Content-Length"))->req_header;
    // TODO: maybe strlen above returns incorrect length because of null byte?
    size_t content_len_str_size = header_content_len->value_len;
    char   content_len_str[content_len_str_size + 1];

    if ( header_content_len == NULL ) {
        return header_flags;
    }

    header_flags |= HEADER_EXISTS;

    // TODO: define is_integer
    if ( !is_integer(header_content_len->value, content_len_str_size) ) {
        return header_flags;
    }

    header_flags |= HEADER_VALUE_VALID;

    memcpy(content_len_str, header_content_len->value, content_len_str_size);
    // set null byte at end of string for call to `strtoumax`:
    *(content_len_str + content_len_str_size + 1) =
        '\x00'; // maybe change to memset?

    uintmax_t content_length = strtoumax(content_len_str, NULL, 10);

    if ( content_length > max_content_length ) {
        return (header_flags ^ HEADER_VALUE_VALID) | HEADER_VALUE_EXCEEDS_MAX;
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
        return HTTP_ENTITY_TOO_LARGE;
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
 * @brief needs refactoring
 *
 * @param servinfo
 * @return int
 */
evutil_socket_t local_socket_bind_listen(const char *restrict port) {
    struct addrinfo *servinfo = get_local_addrinfo(port);
    struct addrinfo *servinfo_next;
    struct sockaddr *sockaddr = servinfo->ai_addr; // get_sockaddr(servinfo);
    int              status;
    evutil_socket_t  main_sockfd;

    for ( servinfo_next = servinfo; servinfo_next != NULL;
          servinfo_next = servinfo_next->ai_next ) {

        main_sockfd =
            socket(servinfo_next->ai_family, servinfo_next->ai_socktype,
                   servinfo_next->ai_protocol);

        if ( main_sockfd == EVUTIL_INVALID_SOCKET ) {
            perror("socket");
            continue;
        }

        status = evutil_make_listen_socket_reuseable(main_sockfd);
        if ( status < 0 ) {
            perror("evutil_make_listen_socket_reusable");
            continue;
        }

        status = bind(main_sockfd, servinfo_next->ai_addr,
                      servinfo_next->ai_addrlen);
        if ( status != 0 ) {
            /*On Unix, returns -1 on error. On Windows, returns
      SOCKET_ERROR, for which I can't find a libevent specific
      implementation. But if no error occurs, 0 is returned both on
      Windows and Unix. So this should be fine.*/
            perror("bind");
            continue;
        }

        status = listen(main_sockfd, BACKLOG);
        if ( status < 0 ) {
            perror("listen");
            continue;
        }

        break;
    }

    catchExcp(servinfo_next == NULL, "local_socket_bind_listen error", 1);

    freeaddrinfo(servinfo);

    return main_sockfd;
}

struct addrinfo *get_local_addrinfo(const char *restrict port) {
    struct addrinfo  hints;
    struct addrinfo *res;
    int              status;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;

    status = getaddrinfo(NULL, port, &hints, &res);

    catchExcp(status != 0, gai_strerror(status), 1);

    return res;
}

int is_integer(const char str[], int str_len) {
    // 0 = 0x30, 9 = 0x39
    char ch;

    for ( int i = 0; i < str_len; i++ ) {
        ch = str[i];
        if ( ch < 0x30 || ch > 0x39 ) {
            return 0;
        }
    }

    return 1;
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
