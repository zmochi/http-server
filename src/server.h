#ifndef __MAIN_H
#define __MAIN_H

#include <http.h> /* user exposed header file, includes http_res, http_req, enum http_method... */
#include <src/headers.h>
#include <src/parser.h>
#include <src/queue.h>
#include <src/response.h>
#include <src/status_codes.h>
#ifdef _WIN32
#include <winsock.h>
#else // Unix probably?
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#endif

/* cross-platform, C standard libraries: */
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#define SOCKET_ERROR -1

struct recv_buffer {
    char  *buffer;
    size_t bytes_parsed, bytes_received;
    size_t capacity;
    bool   headers_parsed, content_parsed;
};

struct client_data {
    int                sockfd;
    struct conn_data  *event;
    struct queue       send_queue;
    struct recv_buffer recv_buf;
    http_req           request;
    bool               close_requested;
};

#endif /* __MAIN_H */
