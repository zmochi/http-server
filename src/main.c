#include "main.h"
/* defines socket_t */
#include "event_loop.h"
#include "headers.h"
#include "http_limits.h"
#include "http_utils.h"
#include "parser.h"
#include "queue.h"
#include "status_codes.h"

/* internal libs: */
#include <event2/util.h>

/* for log10() function used in http_respond_fallback */
#include <math.h>
#include <stdlib.h>
#include <string.h>

static config         server_conf;
static struct timeval CLIENT_TIMEOUT;

#define DFLT_TIMEOUT {.tv_sec = 5, .tv_usec = 0}

#define CHECK_CORRUPT_CALL(con_data, sockfd)                                   \
    {                                                                          \
        if ( con_data->event->sockfd != sockfd ) {                             \
            LOG_ERR("critical: con_data socket and callback sockfd are not "   \
                    "equal!");                                                 \
            exit(1);                                                           \
        }                                                                      \
    }

typedef enum {
    RECV_NODATA,
    CON_RESET,
    RECV_CLIENT_CLOSED_CON,
    SUCCESS,
} recv_flags;

static inline struct send_buffer *dequeue_send_buf(struct queue *queue) {
    return list_entry(dequeue(queue), struct send_buffer, entry);
}
static inline void enqueue_send_buf(struct queue       *queue,
                                    struct send_buffer *send_buf) {
    enqueue(queue, &send_buf->entry);
}
static inline struct send_buffer *peek_send_buf(struct queue *queue) {
    return list_entry(queue->head, struct send_buffer, entry);
}

struct addrinfo *get_local_addrinfo(const char *port);
int              local_socket_bind_listen(const char *port);
void             accept_cb(socket_t, short, void *);
void             send_cb(socket_t sockfd, short flags, void *arg);

/**
 * @brief Callback function to read data sent from client.
 *
 * After the connection is established (via `accept()` and the accept_cb()
 * callback function), the client may send data. This function receives the
 * data and calls the function that handles the HTTP request's method. Signature
 * matches the required signature for callback function in documentation of
 * `event_new()`.
 */
void recv_cb(socket_t, short, void *);

/**
 * @brief Receives pending data in @sockfd into the recv buffer in @con_data
 *
 * @param sockfd socket of connection
 * @param con_data connection data
 * @return RECV_NODATA if there is no data to receive (but connection hasn't
 * been closed) CONN_RESET if client forcibly closed connection (TCP RST
 * packet) RECV_CLIENT_CLOSED_CON if client gracefully closed connection (TCP
 * FIN packet)
 */
int recv_data(socket_t sockfd, struct client_data *con_data);

/**
 * @brief Callback function that handles closing connections
 *
 * This callback is either triggered manually via libevent's API
 * (event_active()) or triggered automatically when the connection times out.
 * If triggered manually, closes connection only once all queued data was sent.
 * If timed out, discards all data to be sent and closes the connection.
 *
 * @param sockfd socket of connection
 * @param flags libevent flags
 * @param arg struct client_data of connection
 */
void close_con_cb(socket_t sockfd, short flags, void *arg);

int  http_respond(struct client_data *con_data, http_res *response);
void http_respond_builtin_status(struct client_data *con_data,
                                 http_status_code    status_code,
                                 int                 http_res_flags);
static inline int parse_request(struct client_data *con_data,
                                struct http_header *headers_arr,
                                size_t              headers_arr_capstruct);
static inline int parse_content(struct client_data *con_data,
                                struct header_value content_len_header,
                                size_t             *content_len);
static void       reset_http_req(http_req *request);
int               terminate_connection(struct client_data *con_data, int flags);
struct client_data *init_client_data(socket_t socket);

bool finished_sending(struct client_data *con_data);
int  finished_receiving(struct client_data *con_data);

bool is_conf_valid(config conf) {
    bool handler_exists;
    bool timeout_valid;

    handler_exists = conf.handler != NULL;
    timeout_valid  = conf.timeout.tv_sec > 0 || conf.timeout.tv_usec > 0;

    return handler_exists & timeout_valid;
}

int init_server(config conf) {

    server_conf = conf;
    if ( !is_conf_valid(conf) ) {
        LOG_ERR("server configuration invalid");
        exit(1);
    }

    socket_t main_sockfd = local_socket_bind_listen(server_conf.PORT);
    evutil_make_socket_nonblocking(main_sockfd);

    struct event_loop base_loop = {
        .listen_sockfd   = main_sockfd,
        .default_timeout = conf.timeout,
        .read_cb         = recv_cb,
        .write_cb        = send_cb,
        .close_conn_cb   = close_con_cb,
        .new_conn_cb     = accept_cb,
    };

    /* doesn't return until the server terminates */
    ev_init_loop(&base_loop);

    evutil_closesocket(main_sockfd);

    return EXIT_SUCCESS;
}

void accept_cb(socket_t sockfd, short flags, void *event_loop_data) {
    // sockaddr big enough for either IPv4 or IPv6
    // contains info about connection
    struct sockaddr_storage *sockaddr =
        calloc(1, sizeof(struct sockaddr_storage));
    if ( !sockaddr ) HANDLE_ALLOC_FAIL();
    ev_socklen_t sockaddr_size = sizeof(struct sockaddr_storage);

    socket_t incoming_sockfd =
        accept(sockfd, (struct sockaddr *)sockaddr, &sockaddr_size);

    if ( incoming_sockfd ==
         EVUTIL_INVALID_SOCKET ) { // TODO: make this work with catchExcp
        LOG_ERR("accept: %s",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    evutil_make_socket_nonblocking(incoming_sockfd);

    LOG("allocating con_data");
    struct client_data *con_data = init_client_data(incoming_sockfd);
    /* event loop to init event on, event to init, arg to pass to callbacks
     */
    con_data->event = ev_add_conn(event_loop_data, incoming_sockfd, con_data);

    free(sockaddr);
}

/**
 * @brief callback function for when a connection times out OR when connection
 * should be closed manually (using libevent's event_active() to trigger this
 * manually)
 *
 * @param sockfd socket of connection
 * @param flags a bitmask of flags of type `enum ev_flags` defined in
 * `event_loop.h`. SERV_CON_CLOSE indicates server is initiating the
 * termination, CLIENT_CON_CLOSE indicates the client has already closed the
 * connection, and TIMEOUT indicates the connection timed out.
 * @param arg ptr to struct client_data of connection
 */
void close_con_cb(socket_t sockfd, short flags, void *arg) {
    LOG();
    struct client_data *con_data   = (struct client_data *)arg;
    struct recv_buffer *recv_buf   = con_data->recv_buf;
    struct queue       *send_queue = &con_data->send_queue;

    bool timed_out              = flags & TIMEOUT;
    bool server_close_requested = flags & SERV_CON_CLOSE;
    bool client_closed_con      = flags & CLIENT_CON_CLOSE;
    bool unsent_data_exists     = !is_empty(send_queue);

    if ( timed_out ) LOG("timed_out");
    if ( unsent_data_exists ) LOG("unsent_data_exis");
    if ( client_closed_con ) LOG("client_closed_con");
    if ( server_close_requested ) LOG("server_close_requested");
    /* failsafe: don't close connection if close wasn't requested, client didn't
     * close connection or connection didn't timeout */
    if ( !(server_close_requested || client_closed_con || timed_out) ) {
        LOG_ERR("callback triggered when it shouldn't have");
        return;
    }

    /* if unsent data exists, send it and don't close connection.
     * if connection timed out/client closed connection, continue (discard
     * unsent data) */
    if ( unsent_data_exists && !timed_out && !client_closed_con ) {
        return;
    }

    LOG("closing connection");

    if ( recv_buf == NULL )
        LOG_ERR("critical: recv_buf is NULL when connection is closed");
    finished_receiving(con_data);

    /* discard queued data to be sent: each call to finished_sending frees the
     * next buffer in queue of responses to be sent, when `true` is returned,
     * there is nothing more to free */
    while ( !finished_sending(con_data) )
        ;

    ev_remove_conn(con_data->event);

    evutil_closesocket(con_data->sockfd);

    if ( !(con_data->request == NULL) )
        free(con_data->request);
    else {
        LOG_ERR("critical: request is NULL");
        exit(EXIT_FAILURE);
    }

    if ( !(con_data == NULL) )
        free(con_data);
    else {
        LOG_ERR("critical: con_data is NULL");
        exit(EXIT_FAILURE);
    }
    printf("\n");
}

void send_cb(socket_t sockfd, short flags, void *arg) {
    LOG("send_cb");

    struct client_data *con_data = (struct client_data *)arg;

    // CHECK_CORRUPT_CALL(con_data, sockfd);

    bool is_send_queue_empty = is_empty(&con_data->send_queue);

    if ( is_send_queue_empty ) {
        /* nothing to send */
        LOG("nothing to send");
        return;
    }

    /* send pending responses */
    struct send_buffer send_buf = *peek_send_buf(&con_data->send_queue);
    size_t             nbytes = 0, total_bytes = 0;

    nbytes = send(sockfd, send_buf.buffer + send_buf.bytes_sent,
                  send_buf.actual_len - send_buf.bytes_sent, 0);

    if ( nbytes == SOCKET_ERROR ) { // TODO: better error handling
        LOG_ERR("send: %s\n",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    } else if ( nbytes == send_buf.actual_len - send_buf.bytes_sent ) {
        /* all data sent, get next send buffer in the queue.
         * if there are no more buffers and connection should be closed, wake
         * close event */
        if ( finished_sending(con_data) && con_data->close_requested )
            event_wake(con_data->event, EV_CLOSE, SERV_CON_CLOSE);
    } else if ( nbytes < send_buf.actual_len - send_buf.bytes_sent ) {
        // not everything was sent
        peek_send_buf(&con_data->send_queue)->bytes_sent += nbytes;
    } else {
        LOG_ERR("unknown error while sending data");
        exit(1);
    }

    LOG("sent!");
}

bool finished_sending(struct client_data *con_data) {
    if ( is_empty(&con_data->send_queue) ) return true;

    struct send_buffer *send_buf = dequeue_send_buf(&con_data->send_queue);

    catchExcp(send_buf->buffer == NULL,
              "finished_sending: critical error, no send_buf buffer found\n",
              1);

    free(send_buf->buffer);
    free(send_buf);

    return is_empty(&con_data->send_queue);
}

int http_handle_incomplete_req(struct client_data *con_data) {
    LOG(":)");
    /* TODO circular recv: shouldn't resize buffer every time in circular buffer
     */
    int status;
    /* if request is incomplete because we reached buffer capacity,
    realloc: */
    if ( con_data->recv_buf->bytes_received >= con_data->recv_buf->capacity ) {
        /* TODO: change handler_buf_realloc signature to be extensible
        for performance improvements, pass in con_data instead of
        single buffer */
        status = handler_buf_realloc(
            &con_data->recv_buf->buffer, &con_data->recv_buf->capacity,
            MAX_RECV_BUFFER_SIZE, 2 * con_data->recv_buf->capacity);

        // TODO out of memory err in handler_buf_realloc
        switch ( status ) {
            case -2:
                http_respond_builtin_status(con_data, Request_Entity_Too_Large,
                                            SERV_CON_CLOSE);
                terminate_connection(con_data, SERV_CON_CLOSE);
        }
    }

    return EXIT_SUCCESS;
}

static inline int parse_request(struct client_data *con_data,
                                struct http_header *headers_arr,
                                size_t              headers_arr_cap) {
    int status = http_parse_request(
        con_data->recv_buf->buffer, con_data->recv_buf->bytes_received,
        &con_data->request->method, &con_data->request->path,
        &con_data->request->path_len, &con_data->request->minor_ver,
        headers_arr, &con_data->request->num_headers,
        &con_data->recv_buf->bytes_parsed);

    if ( con_data->request->method == M_UNKNOWN ) return HTTP_BAD_REQ;

    return status;
}

static inline int parse_content(struct client_data *con_data,
                                struct header_value content_len_header,
                                size_t             *content_len) {
    return http_parse_content(
        con_data->request->message,
        con_data->recv_buf->bytes_received - con_data->recv_buf->bytes_parsed,
        content_len_header.value, content_len_header.value_len,
        MAX_RECV_BUFFER_SIZE - con_data->recv_buf->bytes_received, content_len);
}

void recv_cb(socket_t sockfd, short flags, void *arg) {
    struct client_data *con_data = (struct client_data *)arg;
    int                 status;
    size_t             *bytes_parsed   = &con_data->recv_buf->bytes_parsed;
    size_t             *bytes_received = &con_data->recv_buf->bytes_received;

    /* this function calls recv() once, populates con_data->recv_buf, and
     * returns appropriate error codes. If there's still data to read after
     * recv() is called, the event loop will call recv_cb again */
    status = recv_data(sockfd, con_data);
    switch ( status ) {
        case RECV_NODATA:
            LOG_ERR("suspicious: No data to receive on an open connection even "
                    "though libevent triggered a read event");
            return;

        case CON_RESET:
            LOG("client forcibly closed connection");
        case RECV_CLIENT_CLOSED_CON:
            LOG("client gracefully closed connection");
            terminate_connection(con_data, CLIENT_CON_CLOSE);
            return;

        case SUCCESS:
            break;

        default:
            LOG_ERR("critical: unknown return value from recv_data()");
            exit(1);
    }

    LOG("received data %.20s", con_data->recv_buf->buffer);

    /* if HTTP headers were not parsed and put in con_data yet: */
    if ( !con_data->recv_buf->headers_parsed ) {
        /* parses everything preceding the content from request, populates
         * @headers array with pointers to the HTTP headers and
         * their values in the original request */
        struct http_header headers[MAX_NUM_HEADERS];
        /* must be initialized to capacity of @headers, after http_parse_request
         * returns its value is changed to the actual nyumber of headers */
        size_t num_headers = MAX_NUM_HEADERS;
        status             = parse_request(con_data, headers, num_headers);

        switch ( status ) {
            case HTTP_BAD_REQ:
                http_respond_builtin_status(con_data, Bad_Request, 0);
                return;

            case HTTP_INCOMPLETE_REQ:
                http_handle_incomplete_req(con_data);
                return;

            case EXIT_SUCCESS:
                break;

            default:
                LOG_ERR(
                    "recv_cb: unexpected return value from http_parse_request. "
                    "terminating server");
                exit(EXIT_FAILURE);
        }

        // statusline + headers are complete:
        // populate headers hashmap
        populate_headers_map(con_data->request->headers, headers, num_headers);
        con_data->recv_buf->headers_parsed = true;
    }

    /* write start address of content (message) to the http request struct in
     * this connection */
    con_data->request->message = con_data->recv_buf->buffer + *bytes_parsed;

    /* special rules for HTTP 1.1 */
    if ( con_data->request->minor_ver == 1 ) {
        const char *HOST_HEADER_NAME = "Host";
        /* host header is required on HTTP 1.1 */
        short host_header_flags = http_extract_validate_header(
            con_data->request->headers, HOST_HEADER_NAME,
            strlen(HOST_HEADER_NAME), NULL, 0);

        if ( !(host_header_flags & HEADER_EXISTS) ) {
            http_respond_builtin_status(con_data, Bad_Request, 0);
            return;
        }
    }

    /* continue parsing HTTP message content (or begin parsing if this is the
     * first time) */
    size_t               content_len        = 0;
    struct header_value *content_len_header = http_get_header(
        con_data->request->headers, "Content-Length", strlen("Content-Length"));
    if ( content_len_header != NULL ) {
        status = parse_content(con_data, *content_len_header, &content_len);
    } else {
        status = HTTP_OK;
    }

    switch ( status ) {
        case HTTP_INCOMPLETE_REQ:
            http_handle_incomplete_req(con_data);
            return; /* wait for more data to become available */

        case HTTP_ENTITY_TOO_LARGE:
            /* closes connection if entity too large, since there is no space to
             * process more additional requests */
            http_respond_builtin_status(con_data, Request_Entity_Too_Large,
                                        SERV_CON_CLOSE);
            return;

        case HTTP_BAD_REQ:
            http_respond_builtin_status(con_data, Bad_Request, 0);
            return;

        case HTTP_OK:
            *bytes_parsed += content_len;
            break;

        default:
            LOG_ERR("recv_cb: unexpected return value from http_parse_content. "
                    "terminating server");
            exit(EXIT_FAILURE);
    }

    con_data->recv_buf->content_parsed = true;

    http_res response = server_conf.handler(con_data->request);

    if ( response.num_headers > MAX_NUM_HEADERS ) {
        LOG_ERR("handler returned response with too many headers, aborting.");
        return;
    }

    http_respond(con_data, &response);

    const char *CONNECTION_HEADER_NAME = "Connection";
    const char *CONNECTION_CLOSE_VALUE = "close";

    if ( http_extract_validate_header(
             con_data->request->headers, CONNECTION_HEADER_NAME,
             strlen(CONNECTION_HEADER_NAME), CONNECTION_CLOSE_VALUE,
             strlen(CONNECTION_CLOSE_VALUE)) &
         HEADER_VALUE_VALID ) {
        terminate_connection(con_data, SERV_CON_CLOSE);
    }

    if ( response.headers_arr != NULL ) free(response.headers_arr);
    if ( response.message != NULL ) free(response.message);

    reset_http_req(con_data->request);

    /* finished processing a single request. */
}

int terminate_connection(struct client_data *con_data, int flags) {

    con_data->close_requested = true;

    event_wake(con_data->event, EV_CLOSE, flags);

    return 0;
}

int recv_data(socket_t sockfd, struct client_data *con_data) {
    ev_ssize_t          nbytes   = 0;
    struct recv_buffer *recv_buf = con_data->recv_buf;

    nbytes = recv(sockfd, recv_buf->buffer + recv_buf->bytes_received,
                  recv_buf->capacity - recv_buf->bytes_received, 0);

    if ( nbytes == SOCKET_ERROR ) {
        switch ( EVUTIL_SOCKET_ERROR() ) {
            case ECONNRESET:
                return CON_RESET;

            case EWOULDBLOCK:
/* EWOULDBLOCK and EAGAIN are the same type of error in this case. some systems
 * define them to be different values so need to have a case for both */
#if EWOULDBLOCK != EAGAIN
            case EAGAIN:
#endif
                return RECV_NODATA;

            default:
                LOG_ERR("critical: %s",
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
                exit(1);
        }
    } else if ( nbytes == 0 ) {
        return RECV_CLIENT_CLOSED_CON;
    }

    recv_buf->bytes_received += nbytes;
    return SUCCESS;
}

struct send_buffer *malloc_init_send_buf(size_t capacity) {

    struct send_buffer *send_buf = calloc(1, sizeof(*send_buf));

    if ( !send_buf ) return NULL;

    send_buf->buffer = malloc(capacity);

    if ( !send_buf->buffer ) {
        free(send_buf);
        return NULL;
    }

    send_buf->capacity = capacity;

    return send_buf;
}

/**
 * @brief [TODO:description]
 * after this functions returns, it is safe to free all data related to
 * @response and @response itself
 *
 * @param con_data [TODO:parameter]
 * @param response [TODO:parameter]
 * @return [TODO:return]
 */
int http_respond(struct client_data *con_data, http_res *response) {
    bool message_exists = response->message != NULL;
    /* the struct send_buffer and associated buffer will be free'd in send_cb.
     * INIT_SEND_BUFFER_CAPACITY must be big enough for HTTP_RESPONSE_BASE_FMT
     * after its been formatted. */
    struct send_buffer *new_send_buf =
        malloc_init_send_buf(INIT_SEND_BUFFER_CAPACITY);
    if ( !new_send_buf ) HANDLE_ALLOC_FAIL();

    char       date[128]; // temporary buffer to pass date string
    int        status_code = response->status_code;
    int        status;
    size_t     buflen, bytes_written = 0;
    ev_ssize_t ret, string_len;

    ret = strftime_gmtformat(date, sizeof(date));
    catchExcp(ret != EXIT_SUCCESS,
              "strftime_gmtformat: couldn't write date into buffer", 1);

    buflen = new_send_buf->capacity;

    const char *HTTP_RESPONSE_BASE_FMT = "HTTP/1.%d %d %s\r\n"
                                         "Server: %s\r\n"
                                         "Date: %s\r\n";

    ret =
        snprintf(new_send_buf->buffer, buflen, HTTP_RESPONSE_BASE_FMT,
                 con_data->request->minor_ver, status_code,
                 stringify_statuscode(status_code), server_conf.SERVNAME, date);

    if ( ret >= buflen ) {
        LOG_ERR("http_respond: Initial capacity of send buffer is not big "
                "enough for the base HTTP response format");
        /* this really shouldn't happen and is permanently fixable by simply
         * increasing the initial capacity, so just exit */
        exit(EXIT_FAILURE);
    } else if ( ret < 0 ) {
        LOG_ERR("http_respond: snprintf: base_fmt: %s", strerror(errno));
        exit(1);
    }

    bytes_written += ret;

    // copy headers to send buffer:
    ret = -1;
    while ( ret < 0 && response->headers_arr != NULL ) {
        ret = copy_headers_to_buf(response->headers_arr, response->num_headers,
                                  new_send_buf->buffer + bytes_written,
                                  new_send_buf->capacity - bytes_written);

        if ( ret == 0 ) {
            /* shouldn't happen, but not a critical error */
            LOG_ERR(
                "copy_headers_to_buf: no bytes written even though there was "
                "at least 1 header to write");
        } else if ( ret == -1 ) {
            ret = handler_buf_realloc(
                &new_send_buf->buffer, &new_send_buf->capacity,
                MAX_SEND_BUFFER_SIZE,
                RECV_REALLOC_MUL * new_send_buf->capacity);
            if ( ret == -2 ) {
                return MAX_BUF_SIZE_EXCEEDED;
            }
        } else if ( ret < -1 ) {
            LOG_ERR("copy_headers_to_buf: unknown return value");
            exit(1);
        }
    }

    bytes_written += ret;

    // TODO: realloc buffer is capacity is not big enough
    char *HEADERS_END_FMT = "\r\n";
    memcpy(new_send_buf->buffer + bytes_written, HEADERS_END_FMT,
           strlen(HEADERS_END_FMT));
    bytes_written += strlen(HEADERS_END_FMT);

    /* append HTTP message */
    if ( message_exists ) {
        if ( response->message_len > new_send_buf->capacity - bytes_written ) {
            // TODO: realloc buffer
            LOG_ERR("reached unimplemented code");
            exit(1);
        }

        memcpy(new_send_buf->buffer + bytes_written, response->message,
               response->message_len);

        bytes_written += response->message_len;

    } else if ( response->message_len != 0 ) {
        LOG_ERR("logic: http response message buffer is null but message_len "
                "is not 0");
    }

    new_send_buf->actual_len = bytes_written;

    enqueue_send_buf(&con_data->send_queue, new_send_buf);

    return 0;
}

/**
 * @brief sends default response for the specified @status_code
 * the response for status code XXX is expected to be found in the root folder
 * specified in config, under the name XXX.html
 *
 * @param con_data client to send response to
 * @param status_code status code of the response
 * @param http_res_flags a bitmask of flags from enum http_res_flag
 */
void http_respond_builtin_status(struct client_data *con_data,
                                 http_status_code    status_code,
                                 int                 http_res_flags) {
    LOG();
    http_res     response;
    size_t       init_file_content_cap = INIT_SEND_BUFFER_CAPACITY;
    const size_t MAX_FILE_READ_SIZE    = 1 << 27;
    char message_filepath[1024]; /* arbitrary size, should be big enough for any
                                   path */
    int status;
    /* for load_file_to_buf call: */
    ev_ssize_t ret;
    size_t     content_len;

    /* this buffer should be dynamically allocated since it might need to be
     * resized, if file contents are too big.
     * will be free'd after calling http_respond inside this function */
    char *file_contents_buf = malloc(init_file_content_cap);
    if ( !file_contents_buf ) HANDLE_ALLOC_FAIL();

    /* create path string of HTTP response with provided status code */
    ret = snprintf(message_filepath, ARR_SIZE(message_filepath), "%s/%d.html",
                   server_conf.ROOT_PATH, status_code);
    catchExcp(ret > ARR_SIZE(message_filepath),
              "snprintf: couldn't write html "
              "filename to buffer\n",
              1);

    LOG("sending error from filename: %s", message_filepath);

    content_len    = 0;
    FILE *msg_file = fopen(message_filepath, "r");
    if ( !msg_file ) {
        LOG_ERR("attempted to open %s. fopen: %s", message_filepath,
                strerror(errno));
        exit(1);
    }

    while ( (ret = load_file_to_buf(msg_file, file_contents_buf,
                                    init_file_content_cap, &content_len)) >=
            0 ) {
        /* resize buffer as needed, if file hasn't been fully read */
        status =
            handler_buf_realloc(&file_contents_buf, &init_file_content_cap,
                                MAX_FILE_READ_SIZE, init_file_content_cap * 2);

        if ( status == -2 ) {
            LOG_ERR("file at %s exceeds max read size, aborting.",
                    message_filepath);
            free(file_contents_buf);
            return;
        }
    }

    if ( ret == -1 && fclose(msg_file) != 0 ) {
        /* reached EOF, failed closing msg_file */
        LOG_ERR("fclose: %s", strerror(errno));
        exit(1);
    } else if ( ret <= -2 ) {
        LOG_ERR("error in load_file_to_buf");
        exit(1);
    }

/* gets base 10 number of digits in a natural number */
#define NUM_DIGITS(num) ((int)(log10((double)num) + 1))

    struct http_header  headers[2];
    struct http_header *content_len_header = &headers[0],
                       *connection_header  = &headers[1];

    response.status_code = status_code;
    response.message     = file_contents_buf;
    response.message_len = content_len;
    response.headers_arr = headers;
    response.num_headers = ARR_SIZE(headers);

    /* stringify number of bytes to be sent in message content, +1 to make
     * space for null byte */
    char content_len_value[NUM_DIGITS(SIZE_T_MAX) + 1];
    ret =
        num_to_str(content_len_value, ARR_SIZE(content_len_value), content_len);
    if ( ret < 0 )
        LOG_ERR("num_to_str: error in writing Content-Length header");

    http_header_init(content_len_header, "Content-Length", content_len_value);

    if ( http_res_flags & SERV_CON_CLOSE ) {
        http_header_init(connection_header, "Connection", "close");
    } else {
        http_header_init(connection_header, "Connection", "keep-alive");
    }

    /* http_respond formats everything into a single message and allocates
     * memory for it. when http_respond returns, all memory allocated to
     * @response can be free'd */
    status = http_respond(con_data, &response);

    free(file_contents_buf);

    switch ( status ) {
        /* if response exceeds max send buffer size: */
        case MAX_BUF_SIZE_EXCEEDED:
            LOG_ERR("response with status code %d exceeds maximum buffer "
                    "size. aborting response.",
                    status_code);
            return;
    }
}

/**
 * @brief initalizes the @request struct in struct client_data
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure to allocate
 * memory
 */
static inline int init_client_request(struct client_data *con_data) {
    con_data->request = calloc(1, sizeof(*con_data->request));
    if ( !con_data->request ) return EXIT_FAILURE;

    con_data->request->headers = malloc_init_hashset();

    return EXIT_SUCCESS;
}

/**
 * @brief initalizes the @recv_buf struct in struct client_data
 * @return EXIT_FAILURE on failure to allocate memory
 */
static inline int init_client_recv_buf(struct client_data *con_data) {
    int request_buffer_capacity = INIT_RECV_BUFFER_SIZE;

    con_data->recv_buf = calloc(1, sizeof(*con_data->recv_buf));
    if ( !con_data->recv_buf ) return EXIT_FAILURE;

    con_data->recv_buf->buffer = calloc(request_buffer_capacity, sizeof(char));

    if ( !con_data->recv_buf->buffer ) {
        /* free successfully allocated data from this function */
        free(con_data->recv_buf);
        return EXIT_FAILURE;
    }

    con_data->recv_buf->capacity = request_buffer_capacity;

    return EXIT_SUCCESS;
}

static inline int init_client_event(struct client_data *con_data) {
    return EXIT_SUCCESS;
}

struct client_data *init_client_data(socket_t socket) {
    int send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;

    struct client_data *con_data = calloc(1, sizeof(struct client_data));
    if ( !con_data ) HANDLE_ALLOC_FAIL();

    if ( init_client_event(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    if ( init_client_recv_buf(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    if ( init_client_request(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    con_data->close_requested = false;

    con_data->sockfd = socket;
    return con_data;
}

static inline void reset_http_req(http_req *request) {
    struct header_hashset *headers     = request->headers;
    char                  *message_buf = request->message;

    reset_header_hashset(headers);
    memset(request, 0, sizeof(*request));

    request->headers = headers;
    request->message = message_buf;
}

int finished_receiving(struct client_data *con_data) {
    struct recv_buffer *recv_buf = con_data->recv_buf;
    http_req           *request  = con_data->request;

    catchExcp(recv_buf == NULL || recv_buf->buffer == NULL,
              "finished_receiving: critical error, no recv_buf found\n", 1);

    free_header_hashset(request->headers);
    free(recv_buf->buffer);
    free(recv_buf);
    return 0;
}

int finish_request_processing(struct client_data *con_data) {
    http_req *request = con_data->request;

    return EXIT_SUCCESS;
}

/**
 * @brief needs refactoring
 *
 * @param servinfo
 * @return int
 */
socket_t local_socket_bind_listen(const char *restrict port) {
    struct addrinfo *servinfo = get_local_addrinfo(port);
    struct addrinfo *servinfo_next;
    struct sockaddr *sockaddr = servinfo->ai_addr; // get_sockaddr(servinfo);
    int              status;
    socket_t         main_sockfd;

    for ( servinfo_next = servinfo; servinfo_next != NULL;
          servinfo_next = servinfo_next->ai_next ) {

        main_sockfd =
            socket(servinfo_next->ai_family, servinfo_next->ai_socktype,
                   servinfo_next->ai_protocol);

        if ( main_sockfd == EVUTIL_INVALID_SOCKET ) {
            perror("socket");
            continue;
        }

        status = evutil_make_listen_socket_reuseable(main_sockfd);
        if ( status < 0 ) {
            perror("evutil_make_listen_socket_reusable");
            continue;
        }

        status = bind(main_sockfd, servinfo_next->ai_addr,
                      servinfo_next->ai_addrlen);
        if ( status != 0 ) {
            /*On Unix, returns -1 on error. On Windows, returns
      SOCKET_ERROR, for which I can't find a libevent specific
      implementation. But if no error occurs, 0 is returned both on
      Windows and Unix. So this should be fine.*/
            perror("bind");
            continue;
        }

        status = listen(main_sockfd, BACKLOG);
        if ( status < 0 ) {
            perror("listen");
            continue;
        }

        break;
    }

    catchExcp(servinfo_next == NULL, "local_socket_bind_listen error", 1);

    freeaddrinfo(servinfo);

    return main_sockfd;
}

struct addrinfo *get_local_addrinfo(const char *restrict port) {
    struct addrinfo  hints;
    struct addrinfo *res;
    int              status;

    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;

    status = getaddrinfo(NULL, port, &hints, &res);

    catchExcp(status != 0, gai_strerror(status), 1);

    return res;
}
