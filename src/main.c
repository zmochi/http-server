#include "main.h"
#include "headers.h"
#include "http_utils.h"
#include "status_codes.h"
#include <sys/socket.h>

/* ##__VA_ARGS__ requires compiling with gcc or clang */
#define LOG_ERR(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)

static config server_conf;

#define CLIENT_TIMEOUT_SEC 10

int init_server(config conf) {
    struct event_base *base;
    evutil_socket_t    main_sockfd;
    int                status;
    struct event      *event_accept;
    struct event      *event_write;

    server_conf = conf;

    base = event_base_new();
    catchExcp(base == NULL, "Couldn't open event base.", 1);

    main_sockfd = local_socket_bind_listen(server_conf.PORT);

    /* event_self_cbarg uses magic to pass event_accept as
        an argument to the event_new cb function */
    struct event_data event_accept_args = {.base = base};

    /* event_accept is triggered when there's a new connection and calls
    accept_cb
     *
     * EV_PERSIST allows reading unlimited data from user, or until the
    callback function runs event_del */
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
    struct event   *event_read, *event_write;
    struct event   *event_close_con;
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
                                EV_TIMEOUT | EV_WRITE, close_con_cb, con_data);
    catchExcp(event_close_con == NULL,
              "event_new: couldn't initialize close-connection event", 1);

    status = event_add(event_read, NULL);
    catchExcp(status == -1, "event_add: couldn't add read event", 1);

    status = event_add(event_write, NULL);
    catchExcp(status == -1, "event_add: couldn't add write event", 1);

    status = event_add(event_close_con, &client_timeout);
    catchExcp(status == -1, "event_add: couldn't add close-connection event",
              1);

    con_data->event->event_read  = event_read;
    con_data->event->event_write = event_write;
    con_data->event->sockfd      = incoming_sockfd;

    free(sockaddr);
}

void close_con_cb(evutil_socket_t sockfd, short flags, void *arg) {
    struct client_data *con_data        = (struct client_data *)arg;
    bool                timed_out       = flags & EV_TIMEOUT;
    bool                close_requested = con_data->close_connection;
    bool                send_buf_empty  = con_data->send_buf == NULL;

    if ( !(close_requested || timed_out) && !send_buf_empty ) {
        return;
    }

    // TODO: close connection
}

void send_cb(evutil_socket_t sockfd, short flags, void *arg) {

    struct client_data *con_data    = (struct client_data *)arg;
    size_t              nbytes      = 0;
    size_t              total_bytes = 0;

    printf("send_cb! actual_len = %lu\n", con_data->send_buf->actual_len);

    if ( con_data->send_buf->actual_len == 0 ) {
        return;
    }

    nbytes = send(
        sockfd, con_data->send_buf->buffer + con_data->send_buf->bytes_sent,
        con_data->send_buf->actual_len - con_data->send_buf->bytes_sent, 0);

    if ( nbytes == SOCKET_ERROR ) { // TODO: better error handling
        fprintf(stderr, "send: %s\n",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    printf("sent!");

    if ( nbytes ==
         con_data->send_buf->actual_len - con_data->send_buf->bytes_sent ) {
        // all data sent
        finished_sending(con_data);
    } else if ( nbytes < con_data->send_buf->actual_len -
                             con_data->send_buf->bytes_sent ) {
        // not everything was sent
        con_data->send_buf->bytes_sent += nbytes;
    } else {
        fprintf(stderr, "Unknown error while sending data\n");
        exit(1);
    }
}

int finished_sending(struct client_data *con_data) {
    struct send_buffer *next = con_data->send_buf->next;

    catchExcp(con_data->send_buf == NULL || con_data->send_buf->buffer == NULL,
              "finished_sending: critical error, no send_buf found\n", 1);

    free(con_data->send_buf->buffer);
    free(con_data->send_buf);

    if ( next != NULL ) {
        con_data->send_buf = con_data->send_buf->next;
    } else {
        // initialize empty buffer
        // TODO: probably don't need to free and allocate, just realloc to INIT
        // size and set actual_len to 0 so we don't send this again. On
        // next write actual_len will be updated and contents overwritten.
        // probably potential vulnerability :)))

        con_data->send_buf = calloc(1, sizeof(*con_data->send_buf));
        con_data->send_buf->buffer =
            calloc(INIT_SEND_BUFFER_CAPACITY, sizeof(char));
        con_data->send_buf->capacity   = INIT_SEND_BUFFER_CAPACITY;
        con_data->send_buf->bytes_sent = 0;
        con_data->send_buf->actual_len = 0;
    }

    return 0;
}

int http_handle_incomplete_req(struct client_data *con_data) {
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

        // TODO out of space err in handler_but_realloc
        switch ( status ) {
            case HTTP_ENTITY_TOO_LARGE:
                http_respond_fallback(con_data, Request_Entity_Too_Large);
                terminate_connection(con_data);
        }
    }

    return EXIT_SUCCESS;
}

int http_handle_bad_request(struct client_data *con_data) {
    http_respond_fallback(con_data, Bad_Request);
    terminate_connection(con_data);
    return EXIT_SUCCESS;
}

void recv_cb(evutil_socket_t sockfd, short flags, void *arg) {
    struct client_data *con_data = (struct client_data *)arg;
    int                 status;
    short               header_flags;

    /* receive the waiting data just once. if there's more data to read, recv_cb
     * will be called again */
    recv_data(sockfd, con_data);

    /* if HTTP headers were not parsed and put in con_data yet: */
    if ( !con_data->recv_buf->headers_parsed ) {
        /* parse headers from request */
        status = http_parse_request(con_data);

        switch ( status ) {
            case HTTP_BAD_REQ:
                http_handle_bad_request(con_data);
                return;
            case HTTP_INCOMPLETE_REQ:
                http_handle_incomplete_req(con_data);
                return;
        }

        // statusline + headers are complete:
        // populate headers hashmap with pointers to phr_header's
        populate_headers_map(con_data);
        con_data->recv_buf->headers_parsed = true;
    }

    con_data->request->message =
        con_data->recv_buf->buffer + con_data->recv_buf->bytes_parsed;

    /* host header is required on HTTP 1.1 */
    host_header_flags = http_extract_validate_header(
        "Host", strlen("Host"), HEADER_HOST_EXPECTED,
        strlen(HEADER_HOST_EXPECTED));

    /* first condition: only enforce this on HTTP 1.1 */
    if ( con_data->request->minor_ver == 1 &&
         !(host_header_flags & (HEADER_EXISTS | HEADER_VALUE_VALID)) ) {
        http_respond_fallback(con_data, Bad_Request);
        terminate_connection(con_data);
        return;
    }

    /* continue parsing HTTP message content (or begin parsing if this is the
     * first time) */
    status = http_parse_content(con_data, &con_data->request->message_length);

    if ( status == HTTP_INCOMPLETE_REQ ) {
        return; // wait for more data to become available
    } else if ( status == HTTP_ENTITY_TOO_LARGE ) {
        http_respond_fallback(con_data, Request_Entity_Too_Large);
        terminate_connection(con_data);
        return;
    } else if ( status == HTTP_BAD_REQ ) {
        http_respond_fallback(con_data, Bad_Request);
        terminate_connection(con_data);
        return;
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
}

int terminate_connection(struct client_data *con_data) {

    finished_receiving(con_data);

    int header_flags = http_extract_validate_header(
        "Connection", strlen("Connection"), "close", strlen("close"));
    if ( header_flags & HEADER_VALUE_VALID ) {
        con_data->close_connection = true;
        close_connection(con_data);
    }

    return 0;
}

int close_connection(struct client_data *con_data) {
    // if ( con_data->recv_buf->buffer == NULL ) {
    //     fprintf(stderr, "close_connection: recv_buffer is NULL when "
    //                     "closing connection!\n");
    // } else {
    //     free(con_data->recv_buf->buffer);
    // }
    //
    // if ( con_data->send_buf->buffer == NULL ) {
    //     fprintf(stderr, "close_connection: send_buffer is NULL when "
    //                     "closing connection!\n");
    // } else {
    //     free(con_data->send_buf->buffer);
    // }

    if ( con_data->request == NULL ) {
        fprintf(stderr,
                "close_connection: request is NULL when closing connection!\n");
    } else {
        free(con_data->request);
    }

    event_free(con_data->event->event_read);
    // event_free(con_data->event->event_write);
    // evutil_closesocket(con_data->event->sockfd);

    if ( con_data == NULL ) {
        fprintf(stderr, "close_connection: con_data is NULL when closing "
                        "connection!\n");
    } else {
        free(con_data);
    }
    return 0;
}

int recv_data(evutil_socket_t sockfd, struct client_data *con_data) {
    ev_ssize_t nbytes = 0;

    nbytes = recv(
        sockfd, con_data->recv_buf->buffer + con_data->recv_buf->bytes_received,
        con_data->recv_buf->capacity - con_data->recv_buf->bytes_received, 0);

    if ( nbytes == SOCKET_ERROR ) {
        switch ( EVUTIL_SOCKET_ERROR() ) {
            case ECONNRESET:
                // TODO: handle connection reset by client
                return -1;    // -1 for unknown error? until the TODO is done

            case EWOULDBLOCK: // Shouldn't happen at all
                fprintf(stderr, "EWOULDBLOCK!\n");
                break;

            default:
                fprintf(stderr, "recv: %s\n",
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
                exit(1);
        }
    }

    con_data->recv_buf->bytes_received += nbytes;
    return 0;
}

int http_respond(struct client_data *con_data, http_res *response) {
    struct send_buffer *new_send_buf = calloc(1, sizeof(*new_send_buf));
    new_send_buf->buffer   = calloc(INIT_SEND_BUFFER_CAPACITY, sizeof(char));
    new_send_buf->capacity = INIT_SEND_BUFFER_CAPACITY;

    char   date[128]; // temporary buffer to pass date string
    int    status_code = response->status_code;
    int    status;
    size_t bytes_written = 0;
    size_t buflen;
    size_t ret;

    ret = strftime_gmtformat(date, sizeof(date));
    catchExcp(ret <= 0, "strftime_gmtformat: couldn't write date into buffer",
              1);

start:
    buflen = new_send_buf->capacity;

    ret =
        snprintf(new_send_buf->buffer, buflen,
                 "HTTP/1.%d %d %s\r\n"
                 "Server: %s\r\n"
                 "Date: %s",
                 con_data->request->minor_ver, status_code,
                 status_codes.storage[status_code - status_codes.smallest_code],
                 server_conf.SERVNAME, date);

    if ( ret >= buflen ) {
        // con_data->send_buffer =
        //     realloc(con_data->send_buffer, SEND_REALLOC_MULTIPLIER *
        //     buflen);
        // handler_buf_realloc(&con_data->send_buffer,
        // &con_data->send_buffer_size,
        //                     MAX_SEND_BUFFER_SIZE,
        //                     SEND_REALLOC_MULTIPLIER * buflen);
        if ( handler_buf_realloc(&new_send_buf->buffer, &new_send_buf->capacity,
                                 MAX_SEND_BUFFER_SIZE,
                                 SEND_REALLOC_MULTIPLIER * buflen) == -1 ) {
            http_respond_fallback(con_data, Server_Error);
            return -1;
        }
        goto start;
    }

    bytes_written += ret;

    // copy headers to send buffer:
    for ( struct http_header *header = response->first_header; header != NULL;
          header                     = header->next ) {
        ret = snprintf(new_send_buf->buffer + bytes_written,
                       new_send_buf->capacity, "%s\r\n", header->header);

        if ( ret >= header->header_len + 1 ) { // out of memory
            // TODO: realloc send_buffer?
        }

        bytes_written += ret;
    }

    ret = 0;

    // load contents of file to buffer, reallocate and keep loading from
    // last place if needed:
    while ( (ret = load_file_to_buf(new_send_buf->buffer + bytes_written,
                                    buflen - bytes_written, &bytes_written,
                                    response->filepath, ret) > 0) ) {
        if ( ret == -1 ) {
            http_respond_fallback(
                con_data,
                404); // TODO: this could trigger when fseek fails OR when
                      // file couldn't be opened, needs improvement
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
    }

    new_send_buf->actual_len = bytes_written;
    return 0;
}

void http_respond_fallback(struct client_data *con_data,
                           http_status_code    status_code) {
    size_t send_buffer_capacity =
        INIT_SEND_BUFFER_CAPACITY; // TODO pls and add checks for NULL

    struct send_buffer *response = calloc(1, sizeof(struct send_buffer));
    response->buffer             = malloc(send_buffer_capacity);
    // we don't need to zero out the memory in response->buffer since
    // snprintf ahead already append a null byte to end of string
    catchExcp(response == NULL, "calloc: couldn't allocate send buffer", 1);
    catchExcp(response->buffer == NULL, "calloc: couldn't allocate send buffer",
              1);

    int    bytes_written;
    size_t msg_bytes_written;
    size_t last_len;
    char   date[128];
    char   message[1024];
    char   message_filepath[128];

    response->buffer   = malloc(128);
    response->capacity = 128;

    bytes_written = snprintf(message_filepath, sizeof(message_filepath),
                             "%s/%d.html", server_conf.ROOT_PATH, status_code);
    printf("sending error from filename: %s/%d.html\n", server_conf.ROOT_PATH,
           status_code);
    catchExcp(bytes_written >= sizeof(message_filepath),
              "http_respond_fallback:\n\tsnprintf: couldn't write html "
              "filename to buffer\n",
              1);

    // TODO: loop and check return code
    load_file_to_buf(message, sizeof(message), &msg_bytes_written,
                     message_filepath, last_len);

    bytes_written = strftime_gmtformat(date, sizeof(date));
    catchExcp(bytes_written <= 0,
              "http_respond_fallback:\n\tstrftime_gmtformat: couldn't write "
              "date in fallback response",
              1);

    bytes_written = snprintf(response->buffer, response->capacity,
                             "HTTP/1.1 %d %s\r\n"
                             "Server: %s\r\n"
                             "Date: %s\r\n\r\n"
                             "%s",
                             status_code, stringify_statuscode(status_code),
                             server_conf.SERVNAME, date, message);

    catchExcp(
        bytes_written >= response->capacity,
        "http_respond_fallback:\n\tsnprintf: couldn't write to send buffer", 1);

    response->actual_len = bytes_written;
    printf("send buffer contains:\n%s\nsend_buffer_capacity: %lu\n",
           response->buffer, response->capacity);

    con_data->append_response(con_data, response);
}

int append_response(struct client_data *con_data,
                    struct send_buffer *response) {
    size_t send_buffer_capacity = INIT_SEND_BUFFER_CAPACITY;

    if ( con_data->send_buf == NULL ) {
        con_data->send_buf = response;
        con_data->last     = con_data->send_buf;
    } else {
        con_data->last->next = response;
        con_data->last       = response;
    }
    return 0;
}

int http_respond_notfound(struct client_data *con_data) {
    http_res response = {
        .num_headers  = 0,
        .first_header = NULL,
        .last_header  = NULL,
        .status_code  = 404,
    };

    char filepath[strlen(server_conf.ROOT_PATH) + strlen("/404.html") + 1];
    sprintf(filepath, "%s%s", server_conf.ROOT_PATH, "/404.html");

    response.filepath = filepath;

    http_respond(con_data, &response);

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

    con_data->recv_buf         = calloc(1, sizeof(*con_data->recv_buf));
    con_data->recv_buf->buffer = calloc(request_buffer_capacity, sizeof(char));
    con_data->recv_buf->capacity = request_buffer_capacity;
    con_data->request            = calloc(1, sizeof(*con_data->request));
    con_data->event              = event;

    catchExcp(con_data->recv_buf == NULL,
              "calloc: couldn't allocate recv buffer", 1);
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
    catchExcp(con_data->send_buf == NULL || con_data->send_buf->buffer == NULL,
              "finished_receiving: critical error, no recv_buf found\n", 1);

    struct recv_buffer *recv_buf = con_data->recv_buf;
    free(recv_buf->buffer);
    free(recv_buf);
    return 0;
}

// TODO: add documentation for transfer_encoding part

/**
 * @brief Manages content in the request part of the specified `con_data`
 * Marks the content as parsed in `con_data` if the user specified
 * Content-Length matches the number of bytes received (Assuming the headers
 * were parsed and put into the hashmap before calling this function), and
 * reallocates `recv_buffer` from `con_data` Content_Length > recv buffer
 * capacity. Sets `bytes_parsed` in `con_data`.
 *
 * @param con_data Connection data to manage
 * @param content_length Pointer to content_length, to be set by the method
 * to the content length specified by the request
 * @return HTTP_INCOMPLETE_REQ when the Content-Length header value < bytes
 * received via recv
 * HTTP_ENTITY_TOO_LARGE when the user-specified Content-Length is bigger
 * than maximum recv buffer size HTTP_BAD_REQ if the Content-Length header
 * has an invalid value.
 */
int http_parse_content(struct client_data *con_data, size_t *content_length) {

    short header_flags = http_extract_content_length(
        content_length,
        MAX_RECV_BUFFER_SIZE - con_data->recv_buf->bytes_parsed);

    if ( header_flags & HEADER_EXISTS ) {
        if ( header_flags & HEADER_VALUE_VALID ) {

            // this call can be optimized since we don't need to reallocate
            // space for request line + headers
            handler_buf_realloc(
                &con_data->recv_buf->buffer, &con_data->recv_buf->capacity,
                MAX_RECV_BUFFER_SIZE,
                *content_length + con_data->recv_buf->bytes_parsed);

            if ( con_data->recv_buf->bytes_received <
                 *content_length + con_data->recv_buf->bytes_parsed ) {
                return HTTP_INCOMPLETE_REQ;
            }

            // we choose to trust the user-supplied Content-Length value
            // here as long as its smaller than the maximum buffer size.
            // this might pose a problem if the recv_buffer wasn't cleared
            // somehow for this connection, but this shouldn't happen.
            con_data->recv_buf->bytes_parsed += *content_length;
            con_data->recv_buf->content_parsed = true;

            return 0;
        } else { // Invalid Content-Length value
            if ( header_flags & HEADER_VALUE_EXCEEDS_MAX ) {
                return HTTP_ENTITY_TOO_LARGE;
            } else {
                return HTTP_BAD_REQ;
            }
        }
    }

    // TODO: define http_extract_transfer_encoding
    header_flags = http_extract_validate_header("Transfer-Encoding",
                                                strlen("Transfer-Encoding"),
                                                "chunked", strlen("chunked"));

    if ( header_flags & HEADER_EXISTS && header_flags & HEADER_VALUE_VALID ) {
        // TODO: procedure for transfer encoding
    } else { // no content / invalid header value

        // RFC 2616, 3.6.1, ignore Transfer-Encoding's the server doesn't
        // understand, so we don't terminate on invalid header value
        con_data->recv_buf->content_parsed = true;
    }

    return 0; // success
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
    // http_parse_request (Or actually phr_parse_request that is called from
    // it) returns the *total* length of the HTTP request line + headers for
    // each call, so for each iteration we use = instead of +=
    *bytes_parsed = phr_parse_request(
        buffer, buffer_len, &request->method, &request->method_len,
        &request->path, &request->path_len, &request->minor_ver,
        request->headers, &request->num_headers, *bytes_parsed);

    // switch ( *bytes_parsed ) {
    //     case HTTP_BAD_REQ:             // TODO: Bad request?
    //         return 1;                  // return 1 if request has invalid
    //         format break;
    //     case HTTP_INCOMPLETE_REQ:      // Incomplete request
    //         return 2;                  // return 2 if request is
    //         incomplete
    //     default:
    //         assert(*bytes_parsed > 0); // TODO: is this good practice? we
    //         // always expect bytes_read >= -2
    //         break;
    // }

    return 0; // success
}

// int http_parse_request(char **buffer, size_t buffer_len, http_req
// *req_struct,
//                        int bytes_read) {
//
//     bytes_read = phr_parse_request(
//         *buffer, buffer_len, &req_struct->method,
//         &req_struct->method_len, &req_struct->path,
//         &req_struct->path_len, &req_struct->minor_ver,
//         req_struct->headers, &req_struct->num_headers, bytes_read);
//
//     // TODO: maybe move method validation and others here, to spare
//     // receiving and parsing the entire HTTP message before responding?
//
//     return bytes_read;
// }
