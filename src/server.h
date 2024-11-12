#ifndef __MAIN_H
#define __MAIN_H

#include <http.h> /* user exposed header file, includes http_res, http_req, enum http_method... */
#include <src/headers.h>
#include <src/mempool.h>
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

/* http request struct for inner use, hidden from user */
struct http_request {
    struct mempool *req_mempool;
    /* an independent buffer holding the request path */
    struct buffer path;
    /* the actual buffer for `path` member above, grouped together with the
     * request struct */
    char             pathbuf[URI_PATH_LEN_LIMIT];
    struct buffer    message;
    enum http_method method;
    int              minor_ver;
    /* hashset of headers of HTTP req, each headers value is copied into a
     * buffer inside this struct and is indepedent of the recv buffer */
    struct header_hashset *headers;
    size_t                 num_headers;
    /* points to content of HTTP req (points inside recv_buffer) from client */
};

struct client_data {
    int               sockfd;
    struct conn_data *event;
    struct mempool   *client_mempool;
    struct queue      send_queue;
    struct buffer     recv_buf;
    /* number of bytes received and parsed in current request */
    size_t bytes_received, bytes_parsed;
    /* if headers and content were parsed in current request */
    bool headers_parsed, content_parsed;
    /* parsed request goes here */
    struct http_request request;
    /* if the server wants to close the connection */
    bool close_requested;
};

#endif /* __MAIN_H */
