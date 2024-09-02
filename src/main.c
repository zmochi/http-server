#include "main.h"
#include "headers.h"
#include "http_limits.h"
#include "http_utils.h"
#include "parser.h"
#include "status_codes.h"

/* libevent: */
#include <event2/event.h>

/* internal libs: */
#include "../libs/picohttpparser/picohttpparser.h"

/* for log10() function used in http_respond_fallback */
#include <math.h>
#include <stdlib.h>
#include <string.h>

static config         server_conf;
static struct timeval CLIENT_TIMEOUT;

#define DFLT_CLIENT_TIMEOUT_SEC 3

#define CHECK_CORRUPT_CALL(con_data, sockfd)                                   \
    {                                                                          \
        if ( con_data->event->sockfd != sockfd ) {                             \
            LOG_ERR("critical: con_data socket and callback sockfd are not "   \
                    "equal!");                                                 \
            exit(1);                                                           \
        }                                                                      \
    }

typedef evutil_socket_t socket_t;

typedef enum {
    RECV_NODATA      = 1,
    CON_RESET        = 2,
    SERV_CON_CLOSE   = 4,
    CLIENT_CON_CLOSE = 8,
/* SERV_CON_CLOSE and CLIENT_CON_CLOSE are used in event_active() when signaling
 * connection close event. the event might get the EV_TIMEOUT flag from libevent
 * so make sure all flags the event's callback can receive are different: */
#if EV_TIMEOUT == SERV_CON_CLOSE || EV_TIMEOUT == CLIENT_CON_CLOSE
#error "critical: EV_TIMEOUT is equal to existing flags"
#endif
} con_flags;

struct addrinfo   *get_local_addrinfo(const char *port);
int                local_socket_bind_listen(const char *port);
static void        http_header_init(struct http_header *header,
                                    const char *header_name, const char *header_value);
static inline void http_free_response_headers(http_res *response);
void               accept_cb(evutil_socket_t, short, void *);
void               send_cb(evutil_socket_t sockfd, short flags, void *arg);

/**
 * @brief Callback function to read data sent from client.
 *
 * After the connection is established (via `accept()` and the accept_cb()
 * callback function), the client may send data. This function receives the
 * data and calls the function that handles the HTTP request's method. Signature
 * matches the required signature for callback function in documentation of
 * `event_new()`.
 */
void recv_cb(evutil_socket_t, short, void *);

/**
 * @brief Receives pending data in @sockfd into the recv buffer in @con_data
 *
 * @param sockfd socket of connection
 * @param con_data connection data
 * @return RECV_NODATA if there is no data to receive (but connection hasn't
 * been closed) CONN_RESET if client forcibly closed connection (TCP RST
 * packet) CLIENT_CON_CLOSE if client gracefully closed connection (TCP FIN
 * packet)
 */
int recv_data(evutil_socket_t sockfd, struct client_data *con_data);

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
void close_con_cb(evutil_socket_t sockfd, short flags, void *arg);

int         http_respond(struct client_data *con_data, http_res *response);
void        http_respond_fallback(struct client_data *con_data,
                                  http_status_code status_code, int http_res_flags);
int         reset_con_data(struct client_data *con_data);
static void reset_http_req(http_req *request);
int         terminate_connection(struct client_data *con_data, int flags);
struct client_data *init_client_data(struct event_data *event_loop_data,
                                     evutil_socket_t    sockfd);

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
    struct event_base *base;
    evutil_socket_t    main_sockfd;
    int                status;
    struct event      *event_accept;
    struct event      *event_write;

    server_conf = conf;
    if ( !is_conf_valid(conf) ) {
        LOG_ERR("server configuration invalid");
        exit(1);
    }

    base = event_base_new();
    catchExcp(base == NULL, "Couldn't open event base.", 1);

    main_sockfd = local_socket_bind_listen(server_conf.PORT);

    /* event data of the event loop */
    struct event_data event_accept_args = {
        .base    = base /* event loop base */,
        .timeout = conf.timeout /* timeout shared for all clients */,
        .sockfd  = main_sockfd /* listening socket fd */};

    /* event_accept is triggered when there's a new connection and calls
     * accept_cb
     *
     * EV_PERSIST keeps the event active (listening for new connections) instead
     * of sending it to sleep after a single wake-up */
    event_accept =
        event_new(base, main_sockfd, EV_READ | /* EV_WRITE |  */ EV_PERSIST,
                  accept_cb, &event_accept_args);
    catchExcp(event_accept == NULL, "event_new: couldn't initialize read event",
              1);

    status = event_add(event_accept, NULL);
    catchExcp(status == -1, "event_add: couldn't add read event",
              1); // TODO: timeout

    status = event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);
    catchExcp(status == -1, "event_base_loop: couldn't start event loop", 1);

    evutil_closesocket(main_sockfd);
    event_free(event_accept);

    return 0;
}

void accept_cb(evutil_socket_t sockfd, short flags, void *event_loop_data) {
    struct event   *event_read, *event_write, *event_close_con;
    evutil_socket_t incoming_sockfd;
    int             status;

    // sockaddr big enough for either IPv4 or IPv6
    // contains info about connection
    struct sockaddr_storage *sockaddr =
        calloc(1, sizeof(struct sockaddr_storage));
    if ( !sockaddr ) HANDLE_ALLOC_FAIL();
    ev_socklen_t sockaddr_size = sizeof(struct sockaddr_storage);

    /* accept won't block here since accept_cb is called when there's a pending
     * connection */
    incoming_sockfd =
        accept(sockfd, (struct sockaddr *)sockaddr, &sockaddr_size);

    if ( incoming_sockfd ==
         EVUTIL_INVALID_SOCKET ) { // TODO: make this work with catchExcp
        fprintf(stderr, "accept: %s",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    evutil_make_socket_nonblocking(incoming_sockfd);

    /* Initializing connection data, init_client_data allocates neccesary
     * memory */
    struct client_data *con_data =
        init_client_data((struct event_data *)event_loop_data, incoming_sockfd);

    event_read = event_new(con_data->event->base, incoming_sockfd,
                           EV_READ | EV_PERSIST, recv_cb, con_data);
    catchExcp(event_read == NULL, "event_new: couldn't initialize read event",
              1);

    event_write = event_new(con_data->event->base, incoming_sockfd,
                            EV_WRITE | EV_PERSIST, send_cb, con_data);
    catchExcp(event_write == NULL, "event_new: couldn't initialize write event",
              1);

    /* socket must be -1 in event_new() if flags EV_READ or EV_WRITE are not
     * present */
    event_close_con = event_new(con_data->event->base, -1, EV_TIMEOUT,
                                close_con_cb, con_data);
    catchExcp(event_close_con == NULL,
              "event_new: couldn't initialize close-connection event", 1);

    status = event_add(event_read, NULL);
    catchExcp(status == -1, "event_add: couldn't add read event", 1);

    status = event_add(event_write, NULL);
    catchExcp(status == -1, "event_add: couldn't add write event", 1);

    struct timeval client_timeout = con_data->event->timeout;
    status                        = event_add(event_close_con, &client_timeout);
    catchExcp(status == -1, "event_add: couldn't add close-connection event",
              1);

    con_data->event->event_read      = event_read;
    con_data->event->event_write     = event_write;
    con_data->event->event_close_con = event_close_con;
    /* TODO: remove this */
    con_data->event->sockfd = incoming_sockfd;

    free(sockaddr);
}

/**
 * @brief callback function for when a connection times out OR when connection
 * should be closed manually (using libevent's event_active() to trigger this
 * manually)
 *
 * @param sockfd socket of connection
 * @param flags libevent flags
 * @param arg ptr to struct client_data of connection
 */
void close_con_cb(evutil_socket_t sockfd, short flags, void *arg) {
    LOG();
    struct client_data *con_data = (struct client_data *)arg;
    struct recv_buffer *recv_buf = con_data->recv_buf;
    struct send_buffer *send_buf = con_data->send_buf;

    bool timed_out              = flags & EV_TIMEOUT;
    bool server_close_requested = flags & SERV_CON_CLOSE;
    bool client_closed_con      = flags & CLIENT_CON_CLOSE;
    bool unsent_data_exists     = !(con_data->send_buf == NULL);

    if ( timed_out ) LOG("timed_out");
    if ( unsent_data_exists ) LOG("unsent_data_exis");
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
        event_active(con_data->event->event_write, 0, 0);
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

    event_free(con_data->event->event_write);
    event_free(con_data->event->event_read);
    event_free(con_data->event->event_close_con);

    evutil_closesocket(con_data->event->sockfd);

    // free(con_data->event);

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

void send_cb(evutil_socket_t sockfd, short flags, void *arg) {
    LOG("send_cb");

    struct client_data *con_data = (struct client_data *)arg;

    // CHECK_CORRUPT_CALL(con_data, sockfd);

    bool is_send_queue_empty = con_data->send_buf == NULL;

    if ( is_send_queue_empty ) {
        /* nothing to send */
        LOG("nothing to send");
        return;
    }

    /* send pending responses */
    struct send_buffer send_buf = *(con_data->send_buf);
    size_t             nbytes = 0, total_bytes = 0;

    nbytes = send(sockfd, send_buf.buffer + send_buf.bytes_sent,
                  send_buf.actual_len - send_buf.bytes_sent, 0);

    if ( nbytes == SOCKET_ERROR ) { // TODO: better error handling
        fprintf(stderr, "send: %s\n",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    LOG("sent!");

    if ( nbytes == send_buf.actual_len - send_buf.bytes_sent ) {
        /* all data sent, get next send buffer in the queue. */
        finished_sending(con_data);
    } else if ( nbytes < send_buf.actual_len - send_buf.bytes_sent ) {
        // not everything was sent
        con_data->send_buf->bytes_sent += nbytes;
    } else {
        LOG_ERR("unknown error while sending data");
        exit(1);
    }
}

bool finished_sending(struct client_data *con_data) {

    /* if queue is empty */
    if ( con_data->send_buf == NULL ) return true;

    catchExcp(con_data->send_buf->buffer == NULL,
              "finished_sending: critical error, no send_buf buffer found\n",
              1);

    struct send_buffer *next = con_data->send_buf->next;

    free(con_data->send_buf->buffer);
    free(con_data->send_buf);
    con_data->send_buf = NULL;

    /* if there is another buffer to be queued */
    if ( next != NULL ) {
        con_data->send_buf = next;
        return false;
    } else {
        /* queue is empty */
        return true;
    }
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
            case MAX_BUF_SIZE_EXCEEDED:
                http_respond_fallback(con_data, Request_Entity_Too_Large,
                                      SERV_CON_CLOSE);
                terminate_connection(con_data, SERV_CON_CLOSE);
        }
    }

    return EXIT_SUCCESS;
}

void recv_cb(evutil_socket_t sockfd, short flags, void *arg) {
    struct client_data *con_data = (struct client_data *)arg;
    int                 status;

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
        case CLIENT_CON_CLOSE:
            LOG("client gracefully closed connection");
            terminate_connection(con_data, CLIENT_CON_CLOSE);
            return;

        case EXIT_SUCCESS:
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
        struct phr_header headers[MAX_NUM_HEADERS];
        /* must be initialized to capacity of @headers, after http_parse_request
         * returns its value is changed to the actual nyumber of headers */
        size_t num_headers = MAX_NUM_HEADERS;
        status = http_parse_request(con_data, headers, &num_headers);

        switch ( status ) {
            case HTTP_BAD_REQ:
                http_respond_fallback(con_data, Bad_Request, 0);
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
    con_data->request->message =
        con_data->recv_buf->buffer + con_data->recv_buf->bytes_parsed;

    /* special rules for HTTP 1.1 */
    if ( con_data->request->minor_ver == 1 ) {
        const char *HOST_HEADER_NAME = "Host";
        /* host header is required on HTTP 1.1 */
        short host_header_flags = http_extract_validate_header(
            con_data->request->headers, HOST_HEADER_NAME,
            strlen(HOST_HEADER_NAME), NULL, 0);

        if ( !(host_header_flags & HEADER_EXISTS) ) {
            http_respond_fallback(con_data, Bad_Request, 0);
            return;
        }
    }

    /* continue parsing HTTP message content (or begin parsing if this is the
     * first time) */
    status = http_parse_content(con_data, &con_data->request->message_length);

    switch ( status ) {
        case HTTP_INCOMPLETE_REQ:
            http_handle_incomplete_req(con_data);
            return; /* wait for more data to become available */

        case HTTP_ENTITY_TOO_LARGE:
            /* http_respond_fallback sends Connection: close */
            http_respond_fallback(con_data, Request_Entity_Too_Large, 0);
            return;

        case HTTP_BAD_REQ:
            /* http_respond_fallback sends Connection: close */
            http_respond_fallback(con_data, Bad_Request, 0);
            return;

        case EXIT_SUCCESS:
            break;

        default:
            LOG_ERR("recv_cb: unexpected return value from http_parse_content. "
                    "terminating server");
            exit(EXIT_FAILURE);
    }

    http_res response = server_conf.handler(con_data->request);

    if ( response.num_headers > MAX_NUM_HEADERS ) {
        LOG_ERR("handler returned response with too many headers, aborting.");
        return;
    }

    http_respond(con_data, &response);

    if ( response.headers_arr != NULL ) free(response.headers_arr);
    if ( response.message != NULL ) free(response.message);

    reset_http_req(con_data->request);

    /* finished processing a single request. */
}

int terminate_connection(struct client_data *con_data, int flags) {

    event_active(con_data->event->event_close_con, flags, 0);

    return 0;
}

int recv_data(evutil_socket_t sockfd, struct client_data *con_data) {
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
        return CLIENT_CON_CLOSE;
    }

    recv_buf->bytes_received += nbytes;
    return 0;
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
    /* the struct send_buffer and associated buffer will be free'd in send_cb */
    /* TODO: refactor the initialization of a send_buf into a function */
    struct send_buffer *new_send_buf = calloc(1, sizeof(*new_send_buf));
    if ( !new_send_buf ) HANDLE_ALLOC_FAIL();
    new_send_buf->buffer = malloc(INIT_SEND_BUFFER_CAPACITY);
    if ( !new_send_buf->buffer ) {
        free(new_send_buf);
        HANDLE_ALLOC_FAIL();
    }

    /* INIT_SEND_BUFFER_CAPACITY must be big enough for HTTP_RESPONSE_BASE_FMT
     * after its been formatted */
    new_send_buf->capacity = INIT_SEND_BUFFER_CAPACITY;

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
            if ( ret == MAX_BUF_SIZE_EXCEEDED ) {
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

    con_data->append_response(con_data, new_send_buf);

    return 0;
}

static inline void http_header_init(struct http_header *header,
                                    const char         *header_name,
                                    const char         *header_value) {
    header->header_name  = header_name;
    header->header_value = header_value;
}

static inline void http_free_response_headers(http_res *response) {
    struct http_header *next, *header = response->headers_arr;

    while ( header != NULL ) {
        next = header->next;
        free(header);
        header = next;
    }
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
void http_respond_fallback(struct client_data *con_data,
                           http_status_code status_code, int http_res_flags) {
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

        if ( status == MAX_BUF_SIZE_EXCEEDED ) {
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

int append_response(struct client_data *con_data,
                    struct send_buffer *response) {
    size_t send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;

    if ( con_data->send_buf == NULL ) {
        /* send queue empty, make response first */
        con_data->send_buf = response;
        con_data->last     = con_data->send_buf;
    } else {
        /* append the provided response to the queue of stuff to send */
        con_data->last->next = response;
        con_data->last       = response;
    }

    response->next = NULL;

    return 0;
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

static inline int init_client_event(struct client_data *con_data,
                                    struct event_data  *event_loop_data,
                                    socket_t            sockfd) {
    /* freed in close_con_cb */
    con_data->event = calloc(1, sizeof(*con_data->event));
    if ( !con_data->event ) return EXIT_FAILURE;

    con_data->event->base    = event_loop_data->base;
    con_data->event->timeout = event_loop_data->timeout;
    con_data->event->sockfd  = sockfd;

    return EXIT_SUCCESS;
}

struct client_data *init_client_data(struct event_data *event_loop_data,
                                     socket_t           sockfd) {
    int send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;

    struct client_data *con_data = calloc(1, sizeof(struct client_data));
    if ( !con_data ) HANDLE_ALLOC_FAIL();

    if ( init_client_event(con_data, event_loop_data, sockfd) == EXIT_FAILURE )
        HANDLE_ALLOC_FAIL();

    if ( init_client_recv_buf(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    if ( init_client_request(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    con_data->append_response = append_response;

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

int reset_con_data(struct client_data *con_data) {
    int                 request_buffer_capacity = INIT_RECV_BUFFER_SIZE;
    struct event_data  *event                   = con_data->event;
    http_req           *req_data                = con_data->request;
    struct send_buffer *send_buf                = con_data->send_buf;
    struct recv_buffer *recv_buf                = con_data->recv_buf;
    struct send_buffer *last                    = con_data->last;

    // we prefer to free the data and then call calloc() rather than zero
    // out existing data since the buffer since may be bigger than the
    // initial size
    recv_buf->buffer =
        realloc(con_data->recv_buf->buffer, request_buffer_capacity);
    if ( !recv_buf->buffer ) HANDLE_ALLOC_FAIL();

    recv_buf->capacity = request_buffer_capacity;

    memset(con_data, 0, sizeof(*con_data));
    memset(req_data, 0, sizeof(*req_data));
    con_data->event   = event;
    con_data->request = req_data;

    return 0; // success
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
evutil_socket_t local_socket_bind_listen(const char *restrict port) {
    struct addrinfo *servinfo = get_local_addrinfo(port);
    struct addrinfo *servinfo_next;
    struct sockaddr *sockaddr = servinfo->ai_addr; // get_sockaddr(servinfo);
    int              status;
    evutil_socket_t  main_sockfd;

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
