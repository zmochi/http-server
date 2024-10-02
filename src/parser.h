
#ifndef __PARSER_H_
#define __PARSER_H_

#include <http.h>
#include <src/headers.h>

/* for strlen() */
#include <string.h>

enum http_req_status {
    HTTP_OK,
    HTTP_BAD_REQ,
    HTTP_INCOMPLETE_REQ,
    HTTP_ENTITY_TOO_LARGE,
    HTTP_URI_TOO_LONG,
    HTTP_BAD_METHOD,
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

/**
 * @brief checks if request (that has everything up to its content parsed) is
 * in-line with HTTP/1.1 specification
 *
 * @param request request to check against
 * @return true if request is compliant, false otherwise
 */
bool is_request_HTTP_compliant(const http_req *request);

/**
 * @brief parses HTTP request line and headers that starts in @buffer and
 * populates each argument with correct value.
 * enforces HTTP specs on request line and headers
 *
 * @param buffer buffer pointing to request start
 * @param buf_len capacity of @buffer
 * @param method ptr http method variable
 * @param path ptr to variable pointing at start of path in @buffer
 * @param path_len length of path in request line
 * @param minor_version ptr to minor version variable
 * @param header_set struct to copy header values into
 * @param bytes_parsed number of bytes in request line + headers (buffer +
 * bytes_parsed will point at content start when this returns)
 * @return one of http_req_status indicating request status. parameters are
 * guaranteed to be valid only if HTTP_OK is returned
 */
enum http_req_status
http_parse_request(char *buffer, size_t buf_len, enum http_method *method,
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
enum http_req_status http_parse_content(const char *content_bufptr,
                                        size_t      size_content_received,
                                        const char *content_len_header_value,
                                        size_t      content_len_header_valuelen,
                                        size_t      content_len_limit,
                                        size_t     *content_len);

#endif /* __PARSER_H_ */
