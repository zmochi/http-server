#include "http_utils.h"

#include <stdlib.h>
#include <string.h>

int http_parse_request(struct client_data *con_data,
                       struct phr_header header_arr[], size_t *num_headers) {
    char       *buffer        = con_data->recv_buf->buffer;
    size_t      buffer_len    = con_data->recv_buf->capacity;
    http_req   *request       = con_data->request;
    ev_ssize_t *byte_received = &con_data->recv_buf->bytes_received;
    ev_ssize_t *bytes_parsed  = &con_data->recv_buf->bytes_parsed;
    /* phr_parse_request returns the *total* length of the HTTP request line +
     * headers for each call, so for each iteration use = instead of += */
    *bytes_parsed = phr_parse_request(buffer, buffer_len, &request->method,
                                      &request->method_len, &request->path,
                                      &request->path_len, &request->minor_ver,
                                      header_arr, num_headers, *bytes_parsed);

    /* TODO circular recv: continue parsing request from buffer start if buffer
    end was reached */

    switch ( *bytes_parsed ) {
        case HTTP_BAD_REQ: // bad request
            return HTTP_BAD_REQ;

        case HTTP_INCOMPLETE_REQ: // incomplete request
            return HTTP_INCOMPLETE_REQ;

        default:
            return EXIT_SUCCESS;
    }
}

int http_parse_content(struct client_data *con_data, size_t *content_length) {
    short content_length_header_flags;

    /* WARNING: processing user input and using user-provided value
     *
     * http_extract_content_length validates the Content-Length header from user
     * and puts its value in content_length
     */

    /* check if we already got the content length */
    if ( *content_length > 0 ) {
        content_length_header_flags = HEADER_EXISTS | HEADER_VALUE_VALID;
    } else { /* content_length is of type size_t, so if this is reached
                content_length == 0 */
        /* populate content_length variable with value from user */
        content_length_header_flags = http_extract_content_length(
            con_data->request->headers, content_length,
            MAX_RECV_BUFFER_SIZE - con_data->recv_buf->bytes_received);
    }

    if ( !(content_length_header_flags & HEADER_EXISTS) ) {
        /* no Content-Length header, indicate parsing is finished */
        return EXIT_SUCCESS;
    }
    /* if user-provided Content-Length header has an invalid value */
    if ( !(content_length_header_flags & HEADER_VALUE_VALID) ) {
        if ( content_length_header_flags & HEADER_VALUE_EXCEEDS_MAX )
            return HTTP_ENTITY_TOO_LARGE;
        else
            return HTTP_BAD_REQ;
    }

    /* incomplete request: need to receive more data/reallocate buffer, to match
     * user-provided Content-Length value */
    if ( con_data->recv_buf->bytes_received <
         *content_length + con_data->recv_buf->bytes_parsed )
        return HTTP_INCOMPLETE_REQ;

    /* we choose to trust the user-supplied Content-Length value
     * here as long as its smaller than the maximum buffer size, and the total
     * amount of bytes parsed + Content-Length does not exceed the amount of
     * bytes received (checked above)
     *
     * this might pose a problem if the recv_buffer wasn't cleared somehow for
     * this connection, but this shouldn't happen.
     */
    con_data->recv_buf->bytes_parsed += *content_length;
    con_data->recv_buf->content_parsed = true;

    /* indicate parsing is finished */
    return EXIT_SUCCESS;

    // TODO: implement http_extract_transfer_encoding
    content_length_header_flags = http_extract_validate_header(
        con_data->request->headers, "Transfer-Encoding",
        strlen("Transfer-Encoding"), "chunked", strlen("chunked"));

    if ( content_length_header_flags & HEADER_EXISTS &&
         content_length_header_flags & HEADER_VALUE_VALID ) {
        // TODO: procedure for transfer encoding
    } else { // no content / invalid header value

        // RFC 2616, 3.6.1, ignore Transfer-Encoding's the server doesn't
        // understand, so don't terminate on invalid header value
        con_data->recv_buf->content_parsed = true;
    }

    return EXIT_SUCCESS;
}
