#include "main.h"

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
int http_parse_request(struct client_data *con_data,
                       struct phr_header header_arr[], size_t *num_headers);

/**
 * @brief Manages content in the request part of the specified `con_data`
 * Marks the content as parsed in `con_data` if the user specified
 * Content-Length is <= the number of bytes received (Assuming the headers
 * were parsed and put into the hashmap before calling this function). Sets
 * `bytes_parsed`  `con_data` to number of bytes in request if all expected data
 * arrived.
 *
 * @param con_data Connection data to manage
 * @param content_length Pointer to content_length, to be set by the method
 * to the content length specified by the request
 * @return HTTP_INCOMPLETE_REQ when the Content-Length header value < bytes
 * received via recv
 * HTTP_ENTITY_TOO_LARGE when the user-specified Content-Length is bigger
 * than maximum recv buffer size
 * HTTP_BAD_REQ if the Content-Length header has an invalid value.
 * EXIT_SUCCESS if all expected content was received
 */
int http_parse_content(struct client_data *con_data, size_t *content_length);
