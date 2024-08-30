#include "headers.h"
#include "status_codes.h"
#ifdef _WIN32
#include <winsock.h>
#else // Unix probably?
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#endif

/* internal libs: */
#include "../libs/boost/CURRENT_FUNCTION.hpp"
#include "../libs/picohttpparser/picohttpparser.h"

/* libevent: */
#include <event2/event.h>

/* cross-platform, C standard libraries: */
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef __MAIN_H
#define __MAIN_H

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG(fmt, ...)                                                          \
    printf("LOG: %s: " fmt "\n", BOOST_CURRENT_FUNCTION, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)                                                      \
    fprintf(stderr, "ERROR: %s: " fmt "\n", BOOST_CURRENT_FUNCTION,            \
            ##__VA_ARGS__)

// all sizes are in bytes
/* avoid 0 and 1 values since they're used to indicate general success/failure
 */
#define SOCKET_ERROR          -1
#define MAX_BUF_SIZE_EXCEEDED 2

enum http_req_props {
    HTTP_BAD_REQ          = -1,
    HTTP_INCOMPLETE_REQ   = -2,
    HTTP_ENTITY_TOO_LARGE = -3,
};

enum http_header_props {
    MAX_NUM_HEADERS          = 100,
    HEADER_VALUE_VALID       = 2,
    HEADER_EXISTS            = 4,
    HEADER_VALUE_EXCEEDS_MAX = 8,
};

struct event_data { // TODO: change name to client_ev_data
    struct event_base *base;
    evutil_socket_t    sockfd;
    struct timeval     timeout;
    void              *event_read;
    void              *event_write;
    void              *event_close_con;
};

typedef struct {
    const char     *method, *path;
    size_t          method_len, path_len, num_headers;
    int             minor_ver;
    struct hashset *headers;
    size_t          message_length;
    char           *message;
} http_req;

struct send_buffer {
    char               *buffer;
    size_t              bytes_sent, actual_len, capacity;
    struct send_buffer *next;
};

struct recv_buffer {
    char      *buffer;
    ev_ssize_t bytes_parsed, bytes_received;
    size_t     capacity;
    bool       headers_parsed, content_parsed;
};

struct client_data {
    struct event_data  *event;
    struct send_buffer *send_buf;
    /* TODO: doubly linked list instead of singly with last ptr */
    struct send_buffer *last;
    struct recv_buffer *recv_buf;
    http_req           *request;
    bool                close_connection;
    int (*append_response)(struct client_data *con_data,
                           struct send_buffer *response);
};

typedef struct {
    http_status_code    status_code;
    const char         *message;      /* HTTP response content */
    size_t              message_len;
    struct http_header *first_header; /* linked list of headers */
} http_res;

typedef struct {
    char  *ROOT_PATH;
    char  *PORT;
    char  *SERVNAME;
    time_t timeout;
} config;

int init_server(config conf);

#endif /* __MAIN_H */
