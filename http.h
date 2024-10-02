#ifndef __HTTP_H
#define __HTTP_H

#include <src/headers.h>
#include <src/status_codes.h>
#include <sys/time.h>

enum http_method {
    M_GET,
    M_HEAD,
    M_POST,
    M_PUT,
    M_DELETE,
    M_CONNECT,
    M_OPTIONS,
    M_TRACE,
    M_UNKNOWN,
};

typedef struct {
    http_status_code    status_code;
    char               *message;     /* HTTP response content */
    size_t              message_len;
    struct http_header *headers_arr; /* linked list of headers */
    size_t              num_headers;
    int                 http_minor_ver;
    /* bit mask of flags */
    int res_flags;
} http_res;

typedef struct {
    /* an independent buffer holding the request path */
    char            *path;
    size_t           path_len, path_buf_cap;
    enum http_method method;
    int              minor_ver;
    /* hashset of headers of HTTP req, each headers value is copied into a
     * buffer inside this struct and is indepedent of the recv buffer */
    struct header_hashset *headers;
    size_t                 num_headers;
    /* points to content of HTTP req (points inside recv_buffer) from client */
    char  *message;
    size_t message_length;
} http_req;

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

#endif /* __HTTP_H */
