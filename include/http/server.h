#include <http/event_loop.h>
#include <http/headers.h>
#include <http/parser.h>
#include <http/queue.h>
#include <http/request_response.h>
#include <http/status_codes.h>
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

#ifndef __MAIN_H
#define __MAIN_H

#define SOCKET_ERROR -1

struct send_buffer {
    char            *buffer;
    size_t           bytes_sent, actual_len, capacity;
    struct list_item entry;
};

struct recv_buffer {
    char  *buffer;
    size_t bytes_parsed, bytes_received;
    size_t capacity;
    bool   headers_parsed, content_parsed;
};

struct client_data {
    socket_t            sockfd;
    struct conn_data   *event;
    struct queue        send_queue;
    struct recv_buffer *recv_buf;
    http_req           *request;
    bool                close_requested;
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
    char          *ROOT_PATH;
    char          *PORT;
    char          *SERVNAME;
    struct timeval timeout;
    /* generates a reponse to request.
     *  - must use malloc() to allocate http_res.headers_arr, http_res.message
     *  - must set all fields of http_res
     */
    http_res (*handler)(http_req *request);
} config;

int init_server(config conf);

#endif /* __MAIN_H */
