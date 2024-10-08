#include <src/headers.h>

/* for strlen() */
#include <string.h>

#ifndef __PARSER_H_
#define __PARSER_H_

enum http_req_props {
    HTTP_OK,
    HTTP_BAD_REQ,
    HTTP_INCOMPLETE_REQ,
    HTTP_ENTITY_TOO_LARGE,
};

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

/* struct for associating HTTP method string with its enum code */
struct method_str_code {
    const char      *method_str;
    size_t           method_strlen;
    enum http_method method_code;
};

/* macro must match the name format in `enum http_method` */
#define structify_method(method_name)                                          \
    {#method_name, strlen(#method_name), M_##method_name}

static struct method_str_code methods_strings[] = {
    structify_method(GET),     structify_method(HEAD),
    structify_method(POST),    structify_method(PUT),
    structify_method(DELETE),  structify_method(CONNECT),
    structify_method(OPTIONS), structify_method(TRACE),
};

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

/**
 * @brief checks if request (that has everything up to its content parsed) is
 * in-line with HTTP/1.1 specification
 *
 * @param request request to check against
 * @return true if request is compliant, false otherwise
 */
bool is_request_HTTP_compliant(const http_req *request);

int http_parse_request(char *buffer, size_t buf_len, enum http_method *method,
                       const char **path, size_t *path_len, int *minor_version,
                       struct header_hashset *header_set, size_t *bytes_parsed);

/**
 * @brief parses content in HTTP request, given the Content-Length header
 * value. puts the correct size of content in @content_len parameter, or
 * returns a status indicating some kind of failure.
 *
 * @param con_data Connection data to manage
 * @param content_bufptr pointer to start of received content
 * @param size_content_received number of bytes received from client in
 * content_bufptr
 * @param content_len_header_value value of request Content-Len header
 * @param content_len_header_valuelen length of Content-Length value
 * @param content_len_limit maximum Content-Length header value
 * @param content_len pointer to content_len variable, holding the content
 * length in request
 * @return HTTP_INCOMPLETE_REQ when the Content-Length header value < bytes
 * received via recv
 * HTTP_ENTITY_TOO_LARGE when the user-specified Content-Length is bigger
 * than maximum recv buffer size
 * HTTP_BAD_REQ if the Content-Length header has an invalid value.
 * HTTP_OK if all expected content was received
 */
enum http_req_props http_parse_content(const char *content_bufptr,
                                       size_t      size_content_received,
                                       const char *content_len_header_value,
                                       size_t      content_len_header_valuelen,
                                       size_t      content_len_limit,
                                       size_t     *content_len);

#endif /* __PARSER_H_ */
