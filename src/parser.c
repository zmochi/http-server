#include <src/headers.h>
#include <src/http_limits.h>
#include <src/http_utils.h>
#include <src/parser.h>
/* for struct client_data, enum http_method, enum http_header_props */

/* for struct phr_header */
#include <picohttpparser/picohttpparser.h>

#include <stdlib.h>
#include <string.h>

enum http_method get_method_code(const char *method) {
    struct method_str_code known_method;
    size_t                 num_methods = ARR_SIZE(methods_strings);

    for ( unsigned int i = 0; i < num_methods; i++ ) {
        known_method = methods_strings[i];

        if ( strncmp(method, known_method.method_str,
                     known_method.method_strlen) == 0 )
            return known_method.method_code;
    }

    return M_UNKNOWN;
}

enum http_req_status
http_parse_request(char *buffer, size_t buf_len, enum http_method *method,
                   const char **path, size_t *path_len, int *minor_version,
                   struct header_hashset *header_set, size_t *bytes_parsed) {
    /* struct http_header must be a union with struct phr_header or this
     * function breaks :/ */
    struct http_header headers[MAX_NUM_HEADERS];
    /* must be initialized to capacity of @headers, after parse_request
     * returns its value is changed to the actual number of headers */
    size_t internal_num_headers = ARR_SIZE(headers);

    int         internal_bytes_parsed;
    const char *method_in_buffer;
    size_t      method_buffer_len;
    /* phr_parse_request returns the *total* length of the HTTP request line +
     * headers for each call, so for each iteration use = instead of += */
    internal_bytes_parsed = phr_parse_request(
        buffer, buf_len, &method_in_buffer, &method_buffer_len, path, path_len,
        minor_version, (struct phr_header *)headers, &internal_num_headers,
        *bytes_parsed);

    switch ( internal_bytes_parsed ) {
        case -1: // bad request
            return HTTP_BAD_REQ;

        case -2: // incomplete request
            return HTTP_INCOMPLETE_REQ;
    }

    if ( internal_bytes_parsed < 0 )
        LOG_ABORT("Unknown return code from phr_parse_request");

    /* if this code is reached, request parameters (args to phr_parse_request)
     * are initialized */

    if ( *path_len > URI_PATH_LEN_LIMIT ) return HTTP_URI_TOO_LONG;

    if ( (*method = get_method_code(method_in_buffer)) == M_UNKNOWN )
        return HTTP_BAD_METHOD;

    populate_headers_map(header_set, headers, internal_num_headers);

    /* sort of temporary and ugly fix since I can't decide whether http_req
     * struct should be decoupled from the parser module or not, but the
     * parser module should definitely check if request is HTTP compliant */
    const http_req internal_request = {.headers = header_set,
                                       .method = *method,
                                       .path = (char *)*path,
                                       .path_len = *path_len,
                                       .message = NULL,
                                       .minor_ver = *minor_version,
                                       .num_headers = internal_num_headers,
                                       .path_bufcap = *path_len,
                                       .message_length = 0};

    if ( !is_request_HTTP_compliant(&internal_request) ) return HTTP_BAD_REQ;

    /* code above asserts internal_bytes_parsed >= 0 so this cast is legal */
    *bytes_parsed = (size_t)internal_bytes_parsed;

    return HTTP_OK;

    /* TODO circular recv: continue parsing request from buffer start if
    buffer end was reached */
}

enum http_req_status http_parse_content(const char *content_bufptr,
                                        size_t      size_content_received,
                                        const char *content_len_header_value,
                                        size_t      content_len_header_valuelen,
                                        size_t      content_bufcap,
                                        size_t     *content_len) {
    SUPPRESS_UNUSED(content_bufptr);

    ev_ssize_t extracted_content_len = str_to_positive_num(
        content_len_header_value, content_len_header_valuelen);

    if ( extracted_content_len < 0 ) return HTTP_BAD_REQ;

    if ( (size_t)extracted_content_len > content_bufcap )
        return HTTP_ENTITY_TOO_LARGE;

    if ( size_content_received < (size_t)extracted_content_len )
        return HTTP_INCOMPLETE_REQ;

    *content_len = (size_t)extracted_content_len;

    return HTTP_OK;

    // TODO: implement http_extract_transfer_encoding
    /* content_length_header_flags = http_extract_validate_header(
        con_data->request->headers, "Transfer-Encoding",
        strlen("Transfer-Encoding"), "chunked", strlen("chunked"));

    if ( content_length_header_flags & HEADER_EXISTS &&
         content_length_header_flags & HEADER_VALUE_VALID ) {
        // TODO: procedure for transfer encoding
    } else { // no content / invalid header value

        // RFC 2616, 3.6.1, ignore Transfer-Encoding's the server doesn't
        // understand, so don't terminate on invalid header value
        con_data->recv_buf->content_parsed = true;
    } */
}

bool is_request_HTTP_compliant(const http_req *request) {

    /* special rules for HTTP 1.1 */
    if ( request->minor_ver == 1 ) {
        const char *HOST_HEADER_NAME = "Host";
        /* host header is required on HTTP 1.1 */
        enum http_header_props host_header_flags = http_extract_validate_header(
            request->headers, HOST_HEADER_NAME,
            (unsigned int)strlen(HOST_HEADER_NAME), NULL, 0);

        if ( !(host_header_flags & HEADER_EXISTS) ) {
            return false;
        }
    }

    return true;
}
