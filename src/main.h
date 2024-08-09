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
#define HEADER_VALUE_VALID        1
#define HEADER_EXISTS             2
#define HEADER_VALUE_EXCEEDS_MAX  4
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

struct http_header {
    const char         *header;
    uint16_t            header_len;
    struct http_header *next;
};

typedef enum {
    OK                       = 200,
    Bad_Request              = 400,
    Not_Found                = 404,
    Server_Error             = 500,
    Request_Entity_Too_Large = 413,
    Method_Not_Allowed       = 405,
    Request_Timeout          = 408,
    Not_Implemented          = 501,
} http_status_code;

typedef struct {
    http_status_code    status_code;
    const char         *filepath;
    int                 num_headers;
    struct http_header *first_header;
    struct http_header *last_header;
} http_res;

typedef struct {
    const char *ROOT_PATH;
    const char *PORT;
    const char *SERVNAME;
} config;

int  init_server(config conf);
void accept_cb(evutil_socket_t, short, void *);
void send_cb(evutil_socket_t sockfd, short flags, void *arg);

/**
 * @brief Callback function to read data sent from client.
 *
 * After the connection is established (via `accept()` and the accept_cb()
 * callback function), the client may send data. This function receives the
 * data and closes the connection. Signature matches the required signature
 * for callback function in documentation of `event_new()`.
 */
void recv_cb(evutil_socket_t, short, void *);
int  recv_data(evutil_socket_t sockfd, struct client_data *con_data);
int  http_respond(struct client_data *con_data, http_res *response);
void http_respond_fallback(struct client_data *con_data,
                           http_status_code    status_code);
int  populate_headers_map(struct client_data *con_data);
int  http_respond_notfound(struct client_data *con_data);
int  reset_con_data(struct client_data *con_data);
int  terminate_request(struct client_data *con_data);
struct client_data *init_con_data(struct event_data *ev_data);
int                 close_connection(struct client_data *con_data);
int                 http_parse_request(struct client_data *con_data);
int  http_parse_content(struct client_data *con_data, size_t *content_length);
int  http_recv_and_parse_request(evutil_socket_t sockfd, char *buffer,
                                 size_t buffer_len, http_req *http_request,
                                 ev_ssize_t *bytes_received,
                                 ev_ssize_t *bytes_parsed);
int  finished_sending(struct client_data *con_data);
int  finished_receiving(struct client_data *con_data);
void close_con_cb(evutil_socket_t sockfd, short flags, void *arg);
#endif /* __MAIN_H */
