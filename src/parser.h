#include "headers.h"

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

/** TODO: fix documentation
 * @brief Calls `recv()` on `sockfd` and stored the result in `buffer`.
 * Can be called multiple times as long as the request is incomplete, and
 * updates `bytes_received`, `bytes_parsed`, `request` accordingly.
 *
 * Should only be called when there is data to receive!
 * @param sockfd Socket to receive
 * @param buffer Pointer to buffer containing the request
 * @param buffer_len Length/size of `buffer`
 * @param request A special `http_req` struct
 * @param bytes_received Total bytes received from previous calls to this
 * method
 * @param bytes_parsed Total bytes parsed in previous calls to this method
 * @return -1 on illegal HTTP request format
 * -2 on incomplete HTTP request
 * TODO: simplify code
 */
int http_parse_request(char *buffer, size_t buf_len, enum http_method *method,
                       const char **path, size_t *path_len, int *minor_version,
                       struct http_header header_arr[], size_t *num_headers,
                       size_t *bytes_parsed);

/**
 * @brief Manages content in the request part of the specified `con_data`
 * Marks the content as parsed in `con_data` if the user specified
 * Content-Length is <= the number of bytes received (Assuming the headers
 * were parsed and put into the hashmap before calling this function). Sets
 * `bytes_parsed`  `con_data` to number of bytes in request if all expected
 * data arrived.
 *
 * @param con_data Connection data to manage
 * @param content_bufptr pointer to start of received content
 * @param size_content_received number of bytes received in content_bufptr
 * @param content_len_header_value value of request Content-Len header
 * @param content_len_header_valuelen length of Content-Length value
 * @param content_len_limit maximum Content-Length header value
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
                                       size_t     *bytes_parsed);

#endif /* __PARSER_H_ */
