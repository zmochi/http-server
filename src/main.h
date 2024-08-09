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

#include "libs/picohttpparser/picohttpparser.h"

#include <assert.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef __MAIN_H
#define __MAIN_H

// all sizes are in bytes
/* avoid 0 and 1 values since they're used to indicate general success/failure
 */
#define SOCKET_ERROR              -1
#define BACKLOG                   64
#define INIT_BUFFER_SIZE          256
#define INIT_SEND_BUFFER_CAPACITY 256
#define MAX_NUM_HEADERS           100
#define MAX_RECV_BUFFER_SIZE      1073741824 // 1GB
#define HEADER_HOST_EXPECTED      "host"
#define HTTP_BAD_REQ              -1
#define HTTP_INCOMPLETE_REQ       -2
#define HTTP_ENTITY_TOO_LARGE     -3
#define HEADER_VALUE_VALID        2
#define HEADER_EXISTS             4
#define HEADER_VALUE_EXCEEDS_MAX  8
#define SEND_REALLOC_MULTIPLIER   2
#define MAX_SEND_BUFFER_SIZE      MAX_RECV_BUFFER_SIZE

struct event_data { // TODO: change name to client_ev_data
    struct event_base *base;
    evutil_socket_t    sockfd;
    void              *event_read;
    void              *event_write;
};

typedef struct {
    const char       *method, *path;
    size_t            method_len, path_len, num_headers;
    int               minor_ver;
    struct phr_header headers[MAX_NUM_HEADERS];
    size_t            message_length;
    char             *message;
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
    struct send_buffer *last;
    struct recv_buffer *recv_buf;
    http_req           *request;
    bool                close_connection;
    int (*append_response)(struct client_data *con_data,
                           struct send_buffer *response);
};

/* linked list of HTTP headers, embedded in http_res */
struct http_header {
    const char         *header_name;
    const char         *header_value;
    uint16_t            header_len;
    struct http_header *next;
};

typedef struct {
    http_status_code    status_code;
    const char         *message;
    struct http_header *first_header;
} http_res;

typedef struct {
    char  *ROOT_PATH;
    char  *PORT;
    char  *SERVNAME;
    time_t timeout;
} config;

int init_server(config conf);

#endif /* __MAIN_H */
