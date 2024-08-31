#include "main.h"
#include "headers.h"
#include "http_limits.h"
#include "http_utils.h"
#include "status_codes.h"

/* internal libs: */
#include "../libs/picohttpparser/picohttpparser.h"

/* for log10() function used in http_respond_fallback */
#include <math.h>
#include <stdlib.h>
#include <string.h>

static config server_conf;

#define DFLT_CLIENT_TIMEOUT_SEC 3
#define INIT_CLIENT_TIMEOUT     {.tv_sec = CLIENT_TIMEOUT_SEC, .tv_usec = 0}

/* some of these flags are passed to event_active(), they should be negative so
 * they don't accidentally collide with libevent's flags (which are all
 * positive) */
typedef enum {
    RECV_NODATA      = -1,
    CON_RESET        = -2,
    SERV_CON_CLOSE   = -3,
    CLIENT_CON_CLOSE = -4,
} con_flags;

void accept_cb(evutil_socket_t, short, void *);
void send_cb(evutil_socket_t sockfd, short flags, void *arg);

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
void        close_con_cb(evutil_socket_t sockfd, short flags, void *arg);
int         http_respond(struct client_data *con_data, http_res *response);
void        http_respond_fallback(struct client_data *con_data,
                                  http_status_code status_code, int http_res_flags);
int         reset_con_data(struct client_data *con_data);
static void reset_http_req(http_req *request);
int         terminate_connection(struct client_data *con_data);
struct client_data *init_client_data(struct event_data *ev_data);

int  http_parse_request(struct client_data *con_data,
                        struct phr_header header_arr[], size_t *num_headers);
int  http_parse_content(struct client_data *con_data, size_t *content_length);
int  http_recv_and_parse_request(evutil_socket_t sockfd, char *buffer,
                                 size_t buffer_len, http_req *http_request,
                                 ev_ssize_t *bytes_received,
                                 ev_ssize_t *bytes_parsed);
bool finished_sending(struct client_data *con_data);
int  finished_receiving(struct client_data *con_data);

int init_server(config conf) {
    struct event_base *base;
    evutil_socket_t    main_sockfd;
    int                status;
    struct event      *event_accept;
    struct event      *event_write;

    server_conf      = conf;
    int conf_timeout = conf.timeout;

    if ( conf_timeout == 0 ) conf_timeout = DFLT_CLIENT_TIMEOUT_SEC;

    base = event_base_new();
    catchExcp(base == NULL, "Couldn't open event base.", 1);

    main_sockfd = local_socket_bind_listen(server_conf.PORT);

    /* event_self_cbarg uses magic to pass event_accept as
        an argument to the event_new cb function */
    struct event_data event_accept_args = {.base    = base,
                                           .timeout = conf_timeout};

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

void accept_cb(evutil_socket_t sockfd, short flags, void *event_data) {
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
        init_client_data((struct event_data *)event_data);

    event_read = event_new(con_data->event->base, incoming_sockfd,
                           EV_READ | EV_PERSIST, recv_cb, con_data);
    catchExcp(event_read == NULL, "event_new: couldn't initialize read event",
              1);

    event_write = event_new(con_data->event->base, incoming_sockfd,
                            EV_WRITE | EV_PERSIST, send_cb, con_data);
    catchExcp(event_write == NULL, "event_new: couldn't initialize write event",
              1);

    event_close_con = event_new(con_data->event->base, incoming_sockfd,
                                EV_TIMEOUT, close_con_cb, con_data);
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
    con_data->event->sockfd          = incoming_sockfd;

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
    /* don't close connection if close wasn't requested or
     * connection didn't timeout */
    if ( !(server_close_requested || client_closed_con || timed_out) ) return;

    /* if unsent data exists, send it and don't close connection.
     * if connection timed out/client closed connection, continue (discard
     * unsent data) */
    if ( unsent_data_exists && !timed_out && !client_closed_con ) {
        event_active(con_data->event->event_write, 0, 0);
        return;
    }

    LOG("closing connection");
    /* free recv buffer if not free'd already */
    if ( recv_buf == NULL )
        LOG_ERR("critical: recv_buf is NULL when connection is closed");
    finished_receiving(con_data);
    /* free send buffers (and discard data to be sent) if connection timed out
     */
    // TODO: refactor because this code doesn't make sense and decide whether,
    // on timeout, should remaining responses be sent or discarded */
    if ( send_buf != NULL )
        // if ( timed_out )
        /* each call to finished_sending frees the next buffer in queue of
         * responses to be sent, when `true` is returned, there is nothing
         * more to free */
        while ( !finished_sending(con_data) )
            ;

    // TODO: close connection
    event_free(con_data->event->event_write);
    event_free(con_data->event->event_read);
    event_free(con_data->event->event_close_con);

    evutil_closesocket(con_data->event->sockfd);

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

    catchExcp(con_data->send_buf == NULL || con_data->send_buf->buffer == NULL,
              "finished_sending: critical error, no send_buf found\n", 1);

    struct send_buffer *next = con_data->send_buf->next;

    free(con_data->send_buf->buffer);
    free(con_data->send_buf);
    con_data->send_buf = NULL;

    /* if there is another buffer to be queued */
    if ( next != NULL ) {
        con_data->send_buf = next;
        return false;
    } else {
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
                terminate_connection(con_data);
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
            terminate_connection(con_data);
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

    // if-else statements for methods instead of hash/switch statements simply
    // because there aren't that many methods, performance impact should be
    // negligible?
    if ( strncmp(con_data->request->method, "GET",
                 con_data->request->method_len) == 0 ) {
        // do_GET(con_data); // TODO
        http_respond_fallback(con_data, Method_Not_Allowed, SERV_CON_CLOSE);
        terminate_connection(con_data);
    } else {
        http_respond_fallback(con_data, Not_Implemented, SERV_CON_CLOSE);
        terminate_connection(con_data);
    }

    reset_http_req(con_data->request);

    /* finished processing a single request. */
}

int terminate_connection(struct client_data *con_data) {

    // int header_flags = http_extract_validate_header(
    //     "Connection", strlen("Connection"), "close", strlen("close"));
    // if ( header_flags & HEADER_VALUE_VALID ) {
    //     con_data->close_connection = true;
    //     close_connection(con_data);
    // }

    event_active(con_data->event->event_close_con, SERV_CON_CLOSE, 0);

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
 * @brief copies a linked list of headers and formats them into a buffer
 *
 * @param headers list of headers
 * @param buffer buffer to copy formatted headers to
 * @param capacity buffer capacity
 * @return number of bytes written on success, -1 if capacity is too small
 */
ev_ssize_t copy_headers_to_buf(struct http_header *headers, char *buffer,
                               size_t capacity) {
    const int NO_MEM_ERR    = -1;
    size_t    bytes_written = 0;
    /* the buffer start point and buffer capacity change while writing to the
     * buffer. these variables hold the effective buffer and its effective
     * capacity */
    size_t eff_bufcap;
    char  *eff_buf;
    int    ret;

    static const char *HEADER_FMT = "%s: %s\r\n";

    for ( struct http_header *header = headers; header != NULL;
          header                     = header->next ) {
        eff_bufcap = capacity - bytes_written;
        eff_buf    = buffer + bytes_written;

        ret = snprintf(eff_buf, eff_bufcap, HEADER_FMT, header->header_name,
                       header->header_value);

        if ( ret > eff_bufcap ) { // out of memory, capacity too small
            return NO_MEM_ERR;
        } else if ( ret < 0 ) {
            LOG_ERR("snprintf: headers: %s", strerror(errno));
            exit(1);
        }

        bytes_written += ret;
    }

    return bytes_written;
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
    while ( ret < 0 && response->first_header != NULL ) {
        ret = copy_headers_to_buf(response->first_header,
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
                http_respond_fallback(con_data, Request_Entity_Too_Large,
                                      SERV_CON_CLOSE);
                terminate_connection(con_data);
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

    // load contents of file to buffer, reallocate and keep loading from
    // last place if needed:
    /* while ( (ret = load_file_to_buf(new_send_buf->buffer + bytes_written,
                                    buflen - bytes_written, &bytes_written,
                                    response->filepath, ret) > 0) ) {
        if ( ret == -1 ) {
            // TODO: this could trigger when fseek fails OR when file couldn't
            // be opened, needs improvement
            http_respond_fallback(con_data, Not_Found);
            return -1;
        }

        status = handler_buf_realloc(
            &new_send_buf->buffer, &new_send_buf->capacity,
            MAX_SEND_BUFFER_SIZE, 2 * new_send_buf->capacity);

        switch ( status ) {
            case HTTP_ENTITY_TOO_LARGE:
                // TODO
                break;
            default:
                // TODO
                break;
        }
    } */

    /* append HTTP message content if exists */
    if ( response->message != NULL ) {
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
                                    const char         *header_value,
                                    struct http_header *next) {
    header->header_name  = header_name;
    header->header_value = header_value;
    header->next         = next;
}

static inline void http_free_response_headers(http_res *response) {
    struct http_header *next, *header = response->first_header;

    while ( header != NULL ) {
        next = header->next;
        free(header);
        header = next;
    }
}

/**
 * @brief converts a non-negative size_t variable to a string (e.g 100 -> "100")
 * adds a null byte at end of string
 *
 * @param str buffer to place the result in
 * @param strcap capacity of buffer
 * @param num num to stringify
 * @return on success, number of characters written to @str, not including null
 * byte. -1 on failure
 */
static inline ev_ssize_t num_to_str(char *str, size_t strcap, size_t num) {
    ev_ssize_t ret;

    if ( (ret = snprintf(str, strcap, "%zu", num)) >= strcap ) {
        return -1;
    }

    return ret;
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
    size_t       send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;
    const size_t MAX_FILE_READ_SIZE   = 1 << 27;
    char message_filepath[1024]; /* arbitrary size, should be big enough for any
                                   path */
    int status;
    /* for load_file_to_buf call: */
    ev_ssize_t ret;
    size_t     content_len;

    /* this buffer should be dynamically allocated since it might need to be
     * resized, if file contents are too big. will be free'd in send_cb, after
     * sending its contents */
    char *file_contents_buf = malloc(send_buffer_capacity);
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
                                    send_buffer_capacity, &content_len)) >=
            0 ) {
        /* resize buffer as needed, if file hasn't been fully read */
        status =
            handler_buf_realloc(&file_contents_buf, &send_buffer_capacity,
                                MAX_FILE_READ_SIZE, send_buffer_capacity * 2);

        if ( status == MAX_BUF_SIZE_EXCEEDED )
            LOG_ERR("file at %s exceeds max read size", message_filepath);
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

    response.status_code  = status_code;
    response.message      = file_contents_buf;
    response.message_len  = content_len;
    response.first_header = headers;

    /* stringify number of bytes to be sent in message content, +1 to make space
     * for null byte */
    char content_len_value[NUM_DIGITS(SIZE_T_MAX) + 1];
    ret =
        num_to_str(content_len_value, ARR_SIZE(content_len_value), content_len);
    if ( ret < 0 ) LOG_ERR("snprintf: error in writing Content-Length header");

    http_header_init(content_len_header, "Content-Length", content_len_value,
                     connection_header);

    if ( http_res_flags & SERV_CON_CLOSE ) {
        http_header_init(connection_header, "Connection", "close", NULL);
    } else {
        http_header_init(connection_header, "Connection", "keep-alive", NULL);
    }

    /* http_respond formats everything into a single message and allocates
     * memory for it. when http_respond returns, all memory allocated to
     * @response can be free'd */
    http_respond(con_data, &response);
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
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure to allocate memory
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

struct client_data *init_client_data(struct event_data *event) {
    int send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;

    struct client_data *con_data = calloc(1, sizeof(struct client_data));
    if ( !con_data ) HANDLE_ALLOC_FAIL();

    if ( init_client_recv_buf(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    if ( init_client_request(con_data) == EXIT_FAILURE ) HANDLE_ALLOC_FAIL();

    con_data->event           = event;
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

// TODO: add documentation for transfer_encoding part

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
