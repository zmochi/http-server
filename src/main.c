#include "main.h"
#include "headers.h"
#include "http_utils.h"
#include "status_codes.h"

/* for log10() function used in http_respond_fallback */
#include <math.h>

static config server_conf;

int CLIENT_TIMEOUT_SEC;

void accept_cb(evutil_socket_t, short, void *);
void send_cb(evutil_socket_t sockfd, short flags, void *arg);
/**
 * @brief Callback function to read data sent from client.
 *
 * After the connection is established (via `accept()` and the accept_cb()
 * callback function), the client may send data. This function receives the
 * data and closes the connection. Signature matches the required signature
 * for callback function in documentation of `event_new()`.
 */
void recv_cb(evutil_socket_t, short, void *);
void close_con_cb(evutil_socket_t sockfd, short flags, void *arg);
int  recv_data(evutil_socket_t sockfd, struct client_data *con_data);
int  http_respond(struct client_data *con_data, http_res *response);
void http_respond_fallback(struct client_data *con_data,
                           http_status_code    status_code);
int  populate_headers_map(struct client_data *con_data);
int  reset_con_data(struct client_data *con_data);
int  terminate_connection(struct client_data *con_data);
struct client_data *init_con_data(struct event_data *ev_data);
int                 close_connection(struct client_data *con_data);

int  http_parse_request(struct client_data *con_data);
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

    server_conf        = conf;
    CLIENT_TIMEOUT_SEC = conf.timeout;

    base = event_base_new();
    catchExcp(base == NULL, "Couldn't open event base.", 1);

    main_sockfd = local_socket_bind_listen(server_conf.PORT);

    /* event_self_cbarg uses magic to pass event_accept as
        an argument to the event_new cb function */
    struct event_data event_accept_args = {.base = base};

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

    /* Initializing connection data, init_con_data allocates neccesary
     * memory */
    struct client_data *con_data =
        init_con_data((struct event_data *)event_data);
    struct timeval client_timeout = {.tv_sec  = CLIENT_TIMEOUT_SEC,
                                     .tv_usec = 0};

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

    status = event_add(event_close_con, &client_timeout);
    catchExcp(status == -1, "event_add: couldn't add close-connection event",
              1);

    con_data->event->event_read      = event_read;
    con_data->event->event_write     = event_write;
    con_data->event->event_close_con = event_close_con;
    con_data->event->sockfd          = incoming_sockfd;

    free(sockaddr);
}

/**
 * @brief callback function for when a connection times out OR when all data is
 * sent and close_connection flag is set in client_data struct
 *
 *
 * @param sockfd socket of connection
 * @param flags libevent flags
 * @param arg libevent argument
 */
void close_con_cb(evutil_socket_t sockfd, short flags, void *arg) {
    LOG("close_con_cb");
    struct client_data *con_data        = (struct client_data *)arg;
    struct recv_buffer *recv_buf        = con_data->recv_buf;
    struct send_buffer *send_buf        = con_data->send_buf;
    bool                timed_out       = flags & EV_TIMEOUT;
    bool                close_requested = con_data->close_connection;
    bool                send_buf_empty  = con_data->send_buf == NULL;

    if ( !(close_requested || timed_out) && !send_buf_empty ) {
        return;
    }
    /* free recv buffer if not free'd already */
    if ( recv_buf != NULL )
        finished_receiving(con_data);
    /* free send buffers (and discard data to be sent) if connection timed out
     */
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
        LOG_ERR("close_con_cb: request is NULL when closing connection!");
        exit(EXIT_FAILURE);
    }

    if ( !(con_data == NULL) )
        free(con_data);
    else {
        LOG_ERR("close_con_cb: con_data is NULL when closing connection!");
        exit(EXIT_FAILURE);
    }
}

void send_cb(evutil_socket_t sockfd, short flags, void *arg) {
    LOG("send_cb");

    struct client_data *con_data = (struct client_data *)arg;

    // printf("send_cb! actual_len = %lu\n", con_data->send_buf->actual_len);

    if ( con_data->close_connection && con_data->send_buf == NULL ) {
        // event_active(con_data->event->event_close_con, 0, 0);
        terminate_connection(con_data);
        return;
    } else if ( con_data->send_buf == NULL )
        /* nothing to send */
        return;

    struct send_buffer send_buf = *(con_data->send_buf);
    size_t             nbytes = 0, total_bytes = 0;

    nbytes = send(sockfd, send_buf.buffer + send_buf.bytes_sent,
                  send_buf.actual_len - send_buf.bytes_sent, 0);

    if ( nbytes == SOCKET_ERROR ) { // TODO: better error handling
        fprintf(stderr, "send: %s\n",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    printf("sent!");

    if ( nbytes == send_buf.actual_len - send_buf.bytes_sent ) {
        // all data sent
        if ( finished_sending(con_data) && con_data->close_connection )
            terminate_connection(con_data);
        // event_active(con_data->event->event_close_con, 0, 0);
    } else if ( nbytes < send_buf.actual_len - send_buf.bytes_sent ) {
        // not everything was sent
        con_data->send_buf->bytes_sent += nbytes;
    } else {
        LOG_ERR("send_cb: unknown error while sending data");
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
        con_data->send_buf = con_data->send_buf->next;
        return false;
    } else {
        return true;
    }
}

int http_handle_incomplete_req(struct client_data *con_data) {
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
                http_respond_fallback(con_data, Request_Entity_Too_Large);
                terminate_connection(con_data);
        }
    }

    return EXIT_SUCCESS;
}

int http_handle_bad_request(struct client_data *con_data) {
    http_respond_fallback(con_data, Bad_Request);
    return EXIT_SUCCESS;
}

void recv_cb(evutil_socket_t sockfd, short flags, void *arg) {
    struct client_data *con_data = (struct client_data *)arg;
    int                 status;

    /* this function calls recv() once, populates con_data->recv_buf, and
     * returns appropriate error codes. If there's still data to read after
     * recv() is called, the event loop will call recv_cb again */
    // TODO: handle errors from recv_data
    recv_data(sockfd, con_data);

    /* if HTTP headers were not parsed and put in con_data yet: */
    if ( !con_data->recv_buf->headers_parsed ) {
        /* parses everything preceding the content from request, populates
         * con_data->request->headers with pointers to the HTTP headers and
         * their values in the original request */
        status = http_parse_request(con_data);

        switch ( status ) {
            case HTTP_BAD_REQ:
                http_handle_bad_request(con_data);
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
        // populate headers hashmap with pointers to phr_header's
        populate_headers_map(con_data);
        con_data->recv_buf->headers_parsed = true;
    }

    /* write start address of content (message) to the http request struct in
     * this connection */
    con_data->request->message =
        con_data->recv_buf->buffer + con_data->recv_buf->bytes_parsed;

    /* special rules for HTTP 1.1 */
    if ( con_data->request->minor_ver == 1 ) {
        /* host header is required on HTTP 1.1 */
        short host_header_flags =
            http_extract_validate_header("Host", strlen("Host"), NULL, 0);

        if ( !(host_header_flags & HEADER_EXISTS) ) {
            http_handle_bad_request(con_data);
            terminate_connection(con_data);
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
            http_respond_fallback(con_data, Request_Entity_Too_Large);
            terminate_connection(con_data);
            return;

        case HTTP_BAD_REQ:
            /* http_respond_fallback sends Connection: close */
            http_respond_fallback(con_data, Bad_Request);
            terminate_connection(con_data);
            return;

        default:
            LOG_ERR("recv_cb: unexpected return value from http_parse_content. "
                    "terminating server");
            exit(EXIT_FAILURE);
    }

    // if-else statements for methods instead of hash/switch statements simply
    // because there aren't that many methods, performance impact should be
    // negligible?
    if ( strncmp(con_data->request->method, "GET",
                 con_data->request->method_len) ) {
        // do_GET(con_data); // TODO
        http_respond_fallback(con_data, Method_Not_Allowed);
        terminate_connection(con_data);
        return;
    } else {
        // TODO: there are separate codes for method not allowed and method not
        // supported?
        http_respond_fallback(con_data, Method_Not_Allowed);
        terminate_connection(con_data);
        return;
    }

    /* finished processing a single request. */
}

int terminate_connection(struct client_data *con_data) {

    // int header_flags = http_extract_validate_header(
    //     "Connection", strlen("Connection"), "close", strlen("close"));
    // if ( header_flags & HEADER_VALUE_VALID ) {
    //     con_data->close_connection = true;
    //     close_connection(con_data);
    // }

    con_data->close_connection = true;

    event_active(con_data->event->event_close_con, 0, 0);

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
                // TODO: handle connection reset by client
                return -1;    // -1 for unknown error? until the TODO is done

            case EWOULDBLOCK: // Shouldn't happen at all, socket should always
                              // be non-blocking
                LOG_ERR("EWOULDBLOCK!");

            default:
                LOG_ERR("recv: %s",
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
                exit(1);
        }
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
    /* the struct send_buffer and associated buffer will be free'd in send_cb */
    struct send_buffer *new_send_buf = calloc(1, sizeof(*new_send_buf));
    catchExcp(new_send_buf == NULL, "http_respond: calloc", 1);
    new_send_buf->buffer   = malloc(INIT_SEND_BUFFER_CAPACITY);
    new_send_buf->capacity = INIT_SEND_BUFFER_CAPACITY;
    /* INIT_SEND_BUFFER_CAPACITY must be big enough for HTTP_RESPONSE_BASE_FMT
     * after its been formatted */
    catchExcp(new_send_buf->buffer == NULL, "http_respond: malloc", 1);

    char       date[128]; // temporary buffer to pass date string
    int        status_code = response->status_code;
    int        status;
    size_t     ret, buflen, bytes_written = 0;
    ev_ssize_t string_len;

    ret = strftime_gmtformat(date, sizeof(date));
    catchExcp(ret != EXIT_FAILURE,
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
        /* this really shouldn't happen and is fixable by simply increasing the
         * initial capacity, so just exit */
        exit(EXIT_FAILURE);
    }

    bytes_written += ret;

    static const char *HEADER_FMT      = "%s: %s\r\n";
    static const char *HEADER_SKELETON = ": \r\n";

    // copy headers to send buffer:
    for ( struct http_header *header = response->first_header; header != NULL;
          header                     = header->next ) {
        ret = snprintf(new_send_buf->buffer + bytes_written,
                       new_send_buf->capacity - bytes_written, HEADER_FMT,
                       header->header_name, header->header_value);

        /* the last strlen() is the characters always present in a header
         * this weird length check is because we must get some expected length
         * to compare against output of snprintf */
        string_len = strlen(header->header_name) +
                     strlen(header->header_value) + strlen(HEADER_SKELETON);

        if ( ret > string_len ) { // out of memory
            // TODO: realloc send buffer
            LOG_ERR("http_respond: snprintf: headers out of memory");
            exit(1);
        } else if ( ret < 0 ) {
            LOG_ERR("http_respond: snprintf: headers");
            exit(1);
        }

        bytes_written += ret;
    }

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

    if ( response->message != NULL ) {
        ret = snprintf(new_send_buf->buffer + bytes_written,
                       new_send_buf->capacity - bytes_written, "%s\r\n",
                       response->message);

        string_len = strlen(response->message);

        // memcpy(new_send_buf->buffer + bytes_written, response->message,
        // string_len)

        if ( ret >= string_len ) { // out of memory
            // TODO: realloc send_buffer?
        } else if ( ret < 0 ) {
            LOG_ERR("http_respond: snprintf: response->message");
            exit(1);
        }

        bytes_written += ret;
    }

    new_send_buf->actual_len = bytes_written;

    con_data->append_response(con_data, new_send_buf);

    return 0;
}

void http_header_init(struct http_header *header, const char *header_name,
                      const char *header_value, struct http_header *next) {
    header->header_name  = header_name;
    header->header_value = header_value;
    header->next         = next;
}

void http_free_response_headers(http_res *response) {
    struct http_header *next, *header = response->first_header;

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
 */
void http_respond_fallback(struct client_data *con_data,
                           http_status_code    status_code) {
    http_res     response;
    size_t       send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;
    const size_t MAX_FILE_READ_SIZE   = 1 << 27;
    char         message_filepath[256];
    int          status;
    ev_ssize_t   msg_bytes_written;
    /* for load_file_to_buf call: */
    ev_ssize_t ret;
    size_t     read_file_size = 0;

    /* to be free'd in send_cb, after sending its contents */
    char *buffer = malloc(send_buffer_capacity);
    catchExcp(buffer == NULL, "malloc: couldn't allocate send buffer", 1);

    /* create path string of HTTP response with provided status code */
    msg_bytes_written =
        snprintf(message_filepath, sizeof(message_filepath), "%s/%d.html",
                 server_conf.ROOT_PATH, status_code);
    LOG("sending error from filename: %s/%d.html", server_conf.ROOT_PATH,
        status_code);
    LOG("message_filepath: %s", message_filepath);
    catchExcp(msg_bytes_written > strlen(message_filepath),
              "http_respond_fallback: snprintf: couldn't write html "
              "filename to buffer\n",
              1);

    while ( (ret = load_file_to_buf(buffer, send_buffer_capacity,
                                    message_filepath, &read_file_size)) > 0 ) {
        /* resize buffer as needed, if file hasn't been fully read */
        status =
            handler_buf_realloc(&buffer, &send_buffer_capacity,
                                MAX_FILE_READ_SIZE, send_buffer_capacity * 2);

        /* switch for extensibility */
        switch ( status ) {
            case MAX_BUF_SIZE_EXCEEDED:
                LOG_ERR(
                    "http_respond_fallback: file at %s exceeds max read size",
                    message_filepath);
                goto exit_while;
        }
    }

    if ( ret < 0 ) {
        LOG_ERR("http_respond_fallback: error in load_file_to_buf");
        exit(1);
    }

    msg_bytes_written = read_file_size;

exit_while:

    /* first_header to be freed at the end of this function */
    response.status_code                   = status_code;
    response.message                       = buffer;
    response.first_header                  = malloc(sizeof(struct http_header));
    struct http_header *content_len_header = malloc(sizeof(struct http_header));
    /* make space for string (content_length_str) that stores the Content-Length
     * header, in this case the size of the file read. log10(num) + 1 is the
     * number of digits in a base 10 number
     * +1 at the end for null byte */
    int  file_size_num_digits = ((int)log10((double)read_file_size) + 1) + 1;
    char content_len_str[file_size_num_digits];
    /* copy number into string */
    if ( snprintf(content_len_str, file_size_num_digits, "%zu",
                  read_file_size) > file_size_num_digits )
        /* not a very critical error, no need to terminate server */
        LOG_ERR("http_respond_fallback: snprintf: error in writing "
                "Content-Length header");

    catchExcp(response.first_header == NULL || content_len_header == NULL,
              "http_respond_fallback: malloc", 1);

    http_header_init(response.first_header, "Connection", "Close",
                     content_len_header);
    http_header_init(content_len_header, "Content-Length", content_len_str,
                     NULL);
    /* http_respond formats everything into a single message and allocates
     * memory for it. when http_respond returns, all memory allocated to
     * @response can be free'd */
    http_respond(con_data, &response);
    http_free_response_headers(&response);
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

struct client_data *init_con_data(struct event_data *event) {
    int send_buffer_capacity    = INIT_SEND_BUFFER_CAPACITY;
    int request_buffer_capacity = INIT_BUFFER_SIZE;

    struct client_data *con_data = calloc(1, sizeof(struct client_data));
    catchExcp(con_data == NULL,
              "calloc: couldn't allocate client_data when initializing "
              "connection",
              1);

    con_data->append_response = append_response;

    con_data->recv_buf = calloc(1, sizeof(*con_data->recv_buf));
    catchExcp(con_data->recv_buf == NULL,
              "calloc: couldn't allocate recv buffer", 1);

    con_data->recv_buf->buffer = calloc(request_buffer_capacity, sizeof(char));
    con_data->recv_buf->capacity = request_buffer_capacity;
    con_data->request            = calloc(1, sizeof(*con_data->request));
    con_data->event              = event;

    catchExcp(con_data->recv_buf->buffer == NULL,
              "calloc: couldn't allocate recv buffer", 1);
    catchExcp(con_data->request == NULL,
              "calloc: couldn't allocate http request when initializing "
              "connection",
              1);

    return con_data;
}

int reset_con_data(struct client_data *con_data) {
    int                 request_buffer_capacity = INIT_BUFFER_SIZE;
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
    // TODO: check success of realloc
    recv_buf->capacity = request_buffer_capacity;

    memset(con_data, 0, sizeof(*con_data));
    memset(req_data, 0, sizeof(*req_data));
    con_data->event   = event;
    con_data->request = req_data;

    return 0; // success
}

int finished_receiving(struct client_data *con_data) {
    struct recv_buffer *recv_buf = con_data->recv_buf;

    catchExcp(recv_buf == NULL || recv_buf->buffer == NULL,
              "finished_receiving: critical error, no recv_buf found\n", 1);

    free(recv_buf->buffer);
    free(recv_buf);
    return 0;
}

int request_processed(struct client_data *con_data) {
    struct recv_buffer *recv_buf = con_data->recv_buf;

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
    if ( *content_length != 0 ) {
        content_length_header_flags = HEADER_EXISTS | HEADER_VALUE_VALID;
    } else {
        /* populate content_length variable with value from user */
        content_length_header_flags = http_extract_content_length(
            content_length,
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
        "Transfer-Encoding", strlen("Transfer-Encoding"), "chunked",
        strlen("chunked"));

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
int http_parse_request(struct client_data *con_data) {
    char       *buffer        = con_data->recv_buf->buffer;
    size_t      buffer_len    = con_data->recv_buf->capacity;
    http_req   *request       = con_data->request;
    ev_ssize_t *byte_received = &con_data->recv_buf->bytes_received;
    ev_ssize_t *bytes_parsed  = &con_data->recv_buf->bytes_parsed;
    /* phr_parse_request returns the *total* length of the HTTP request line +
     * headers for each call, so for each iteration use = instead of += */
    *bytes_parsed = phr_parse_request(
        buffer, buffer_len, &request->method, &request->method_len,
        &request->path, &request->path_len, &request->minor_ver,
        request->headers, &request->num_headers, *bytes_parsed);

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
