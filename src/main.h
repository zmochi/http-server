#include "headers.h"
#include "queue.h"
#include "status_codes.h"
#ifdef _WIN32
#include <winsock.h>
#else // Unix probably?
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#endif

/* libevent: */
#include <event2/event.h>

/* cross-platform, C standard libraries: */
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#ifndef __MAIN_H
#define __MAIN_H

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
    /* pointers to the method and path in original client recv buf */
    const char *method, *path;
    /* lengths of method and path strings above */
    size_t method_len, path_len;
    size_t num_headers;
    int    minor_ver;
    /* hashset of headers of HTTP req, each headers value is copied into a
     * buffer inside this struct and is indepedent of the recv buffer */
    struct header_hashset *headers;
    /* points to content of HTTP req from client */
    char  *message;
    size_t message_length;
} http_req;

struct send_buffer {
    char            *buffer;
    size_t           bytes_sent, actual_len, capacity;
    struct list_item entry;
};

struct recv_buffer {
    char      *buffer;
    ev_ssize_t bytes_parsed, bytes_received;
    size_t     capacity;
    bool       headers_parsed, content_parsed;
};

struct client_data {
    struct event_data  *event;
    struct queue        send_queue;
    struct recv_buffer *recv_buf;
    http_req           *request;
};

enum res_flags {
    PLACEHOLDER = 1,
};

typedef struct {
    http_status_code    status_code;
    char               *message;     /* HTTP response content */
    size_t              message_len;
    struct http_header *headers_arr; /* linked list of headers */
    size_t              num_headers;
    /* bit mask of flags */
    enum res_flags res_flags;
} http_res;

typedef struct {
    char  *ROOT_PATH;
    char  *PORT;
    char  *SERVNAME;
    time_t timeout;
    /* generates a reponse to request.
     *  - must use malloc() to allocate response.headers_arr, response.message
     *  - must set all fields of http_res
     */
    http_res (*handler)(http_req *request);
} config;

int init_server(config conf);

#endif /* __MAIN_H */
