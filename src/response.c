#include <src/http_limits.h>
#include <src/http_utils.h>
#include <src/queue.h>
#include <src/response.h>
#include <src/status_codes.h>

#include <event2/util.h> /* for ev_ssize_t */
#include <limits.h>      /* for SIZE_T_MAX */
#include <string.h>      /* for strerror() */

/* for internal use in this file */
enum func_return_codes {
    SUCCESS = 0,
    FAIL = 1,
    MAX_BUF_SIZE_EXCEEDED = 2,
};

ev_ssize_t write_http_base_fmt(char *buffer, size_t bufcap, int minor_ver,
                               http_status_code status_code,
                               const char      *server_name) {
    const char *HTTP_RESPONSE_BASE_FMT =
        "HTTP/1.%d %d %s" CRLF "Server: %s" CRLF "Date: %s" CRLF;

    char       date[128]; // temporary buffer to pass date string
    ev_ssize_t ret;

    ret = strftime_gmtformat(date, sizeof(date));
    catchExcp(ret != 0, "strftime_gmtformat: couldn't write date into buffer",
              1);

    ret =
        snprintf(buffer, bufcap, HTTP_RESPONSE_BASE_FMT, minor_ver, status_code,
                 stringify_statuscode(status_code), server_name, date);

    if ( ret < 0 ) {
        LOG_ERR("snprintf: base_fmt: %s", strerror(errno));
        return -1;
    } else if ( (size_t)ret >= bufcap ) { /* >= instead of > since ret does not
                                             include terminating null byte */
        LOG_ERR("Initial capacity of send buffer is not big enough for the "
                "base HTTP response format");
        return -1;
    }

    /* returns number of bytes written not including null character */
    return ret;
}

/**
 * @brief helper function to reallocate send buffer and update ptrs to it
 *
 * @param any for parameters see sendbuf_copy_message documentation
 * @return see sendbuf_copy_message documentation
 */
static inline int realloc_send_buf(struct send_buffer *send_buf, char **eff_buf,
                                   size_t *eff_bufcap) {
    size_t bytes_written = send_buf->capacity - *eff_bufcap;

    if ( handler_buf_realloc(&send_buf->buffer, &send_buf->capacity,
                             MAX_SEND_BUFFER_SIZE,
                             RECV_REALLOC_MUL * send_buf->capacity) == -2 )
        return MAX_BUF_SIZE_EXCEEDED;

    /* in case buffer pointers were modified in handler_buf_realloc, rewrite */
    *eff_buf = send_buf->buffer + bytes_written;
    *eff_bufcap = send_buf->capacity - bytes_written;

    return SUCCESS;
}

/**
 * @brief helper function for format_response, copies specified headers into
 * send buffer
 *
 * @param headers_arr array of headers to format into send buffer
 * @param num_headers size of array
 * @param any for other parameters see sendbuf_copy_message documentation
 * @return see sendbuf_copy_message documentation
 */
static inline int sendbuf_copy_headers(struct send_buffer *send_buf,
                                       struct http_header *headers_arr,
                                       size_t num_headers, char **eff_buf,
                                       size_t *eff_bufcap) {
    ev_ssize_t num_bytes;

    do {
        num_bytes = copy_headers_to_buf(headers_arr, num_headers, *eff_buf,
                                        *eff_bufcap);
        if ( num_bytes == -1 ) {
            if ( realloc_send_buf(send_buf, eff_buf, eff_bufcap) ==
                 MAX_BUF_SIZE_EXCEEDED )
                return MAX_BUF_SIZE_EXCEEDED;
        } else if ( num_bytes < -1 )
            LOG_ABORT("copy_headers_to_buf: unknown return value");
    } while ( num_bytes < 0 );

    *eff_buf += num_bytes;
    *eff_bufcap -= (size_t)num_bytes;
    send_buf->bytes_written += (size_t)num_bytes;

    return SUCCESS;
}

/**
 * @brief helper function for format_response
 *
 * @param content_len value of Content-Length header to format into send buffer
 * @param any for other parameters see sendbuf_copy_message documentation
 * @return see sendbuf_copy_message documentation
 */
static inline int sendbuf_copy_content_len(struct send_buffer *send_buf,
                                           size_t content_len, char **eff_buf,
                                           size_t *eff_bufcap) {

    /* +1 for null byte */
    char               content_len_buf[NUM_DIGITS(SIZE_T_MAX) + 1];
    struct http_header content_len_header;
    /* format response->message_len into string, store in content_len */
    ev_ssize_t ret =
        num_to_str(content_len_buf, ARR_SIZE(content_len_buf), content_len);
    if ( ret <= 0 ) return FAIL;

    http_header_init(&content_len_header, "Content-Length", content_len_buf);

    return sendbuf_copy_headers(send_buf, &content_len_header, 1, eff_buf,
                                eff_bufcap) == MAX_BUF_SIZE_EXCEEDED;
}

/**
 * @brief helper function for format_response, increases send_buf->bytes_written
 * after writing
 *
 * @param send_buf send buffer to copy message into
 * @param message message to copy
 * @param message_len length of message
 * @param eff_buf ptr to buffer variable to advance after writing/change in case
 * of reallocation
 * @param eff_bufcap ptr to capacity variable of above buffer
 * @return MAX_BUF_SIZE_EXCEEDED if maximum buffer size is exceeded, otherwise
 * SUCCESS
 */
static inline int sendbuf_copy_message(struct send_buffer *send_buf,
                                       const char *message, size_t message_len,
                                       char **eff_buf, size_t *eff_bufcap) {
    while ( message_len > *eff_bufcap )
        if ( realloc_send_buf(send_buf, eff_buf, eff_bufcap) ==
             MAX_BUF_SIZE_EXCEEDED ) {
            return MAX_BUF_SIZE_EXCEEDED;
        }

    memcpy(*eff_buf, message, message_len);

    *eff_buf += message_len;
    *eff_bufcap -= message_len;
    send_buf->bytes_written += message_len;

    return SUCCESS;
}

/**
 * @brief formats response into provided struct send_buffer, adds Content-Length
 * header if message exists
 *
 * after this functions returns, it is safe to free all data related to
 * @response and @response itself.
 * if either response->message is NULL or response->message_len is 0, no content
 * is sent with request
 *
 * @param send_buf struct send_buffer to format response into
 * @param response response to format
 * @param server_name name of server in formatted response
 * @return 0 on success, 1 on general failure and 2 if response is too large
 */
int format_response(struct send_buffer *send_buf, http_res *response,
                    const char *server_name) {

    bool message_exists =
        response->message != NULL && response->message_len != 0;
    bool extra_headers_exist = response->headers_arr != NULL;

    ev_ssize_t       ret;
    http_status_code status_code = response->status_code;
    size_t           eff_bufcap = send_buf->capacity;
    char            *eff_buf = send_buf->buffer;

    if ( response->http_minor_ver >= 2 )
        LOG_ABORT("Invalid http minor version in user response");

    ret = write_http_base_fmt(eff_buf, eff_bufcap, response->http_minor_ver,
                              status_code, server_name);
    if ( ret <= 0 ) return FAIL;

    eff_buf += (size_t)ret;
    eff_bufcap -= (size_t)ret;
    send_buf->bytes_written += (size_t)ret;

    /* copy content_len to send buffer if exists: */
    if ( message_exists &&
         sendbuf_copy_content_len(send_buf, response->message_len, &eff_buf,
                                  &eff_bufcap) == MAX_BUF_SIZE_EXCEEDED ) {
        LOG_ERR("maximum buffer size exceeded while copying Content-Length "
                "header");
        return MAX_BUF_SIZE_EXCEEDED;
    }

    // copy headers to send buffer:
    if ( extra_headers_exist &&
         sendbuf_copy_headers(send_buf, response->headers_arr,
                              response->num_headers, &eff_buf,
                              &eff_bufcap) == MAX_BUF_SIZE_EXCEEDED ) {
        LOG_ERR("maximum buffer size exceeded while copying user headers");
        return MAX_BUF_SIZE_EXCEEDED;
    }

    /* copy final CRLF signifying end of headers: */
    while ( eff_bufcap < CRLF_LEN )
        if ( realloc_send_buf(send_buf, &eff_buf, &eff_bufcap) ==
             MAX_BUF_SIZE_EXCEEDED ) {
            LOG_ERR("maximum buffer size exceeded while preparing to copy "
                    "final CRLF");
            return MAX_BUF_SIZE_EXCEEDED;
        }
    memcpy(eff_buf, CRLF, CRLF_LEN);

    eff_buf += CRLF_LEN;
    eff_bufcap -= CRLF_LEN;
    send_buf->bytes_written += CRLF_LEN;

    /* append HTTP message */
    if ( message_exists &&
         sendbuf_copy_message(send_buf, response->message,
                              response->message_len, &eff_buf,
                              &eff_bufcap) == MAX_BUF_SIZE_EXCEEDED ) {
        LOG_ERR("maximum buffer size exceeded trying to copy response "
                "message");
        return MAX_BUF_SIZE_EXCEEDED;
    }

    return SUCCESS;
}
