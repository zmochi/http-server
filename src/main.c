#ifdef _WIN32
#include <winsock.h>
#else // Unix probably?
#include <event2/event.h>
#include <event2/listener.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define SOCKET_ERROR -1

#endif

#include "libs/picohttpparser.h"
#include <assert.h>
#include <stdarg.h> // for vargs, is this Windows compatible?

#define PORT                 "25565"
#define BACKLOG              64
#define INIT_MAX_BUFFER_SIZE 256
#define MAX_NUM_HEADERS      100

struct event_cb_args {
    struct event_base *base;
    void              *event_self;
    void              *data_processor;
};

typedef struct {
    const char       *method, *path;
    size_t            method_len, path_len, body_len, num_headers;
    int               minor_ver;
    struct phr_header headers[MAX_NUM_HEADERS];
    char             *body;

} http_req;

struct addrinfo *get_local_addrinfo(const char *);
struct sockaddr *get_sockaddr(struct addrinfo *);
int              local_socket_bind_listen(const char *);
void             catchExcp(int, const char *, int);
void             accept_cb(evutil_socket_t, short, void *);
void             recv_cb(evutil_socket_t, short, void *);
int              http_parse_request(char **request, http_req *req_struct,
                                    ev_ssize_t bytes_read);
ev_ssize_t http_recv_and_parse_request(evutil_socket_t sockfd, char *buffer,
                                       ev_ssize_t  buffer_len,
                                       http_req   *http_request,
                                       ev_ssize_t *bytes_received,
                                       ev_ssize_t *bytes_parsed);

int init_server(const char *restrict port, void *data_processor) {
    struct event_base *base;
    evutil_socket_t    main_sockfd;
    int                status;
    struct event      *event_read;
    struct event      *event_write;

    base = event_base_new();
    catchExcp(base == NULL, "Couldn't open event base.\n", 1);

    main_sockfd = local_socket_bind_listen(port);

    status = evutil_make_socket_nonblocking(main_sockfd);
    catchExcp(status == -1, "Couldn't make listen socket non-blocking", 1);

    /* event_self_cbarg uses magic to pass event_read as
        an argument to the event_new cb function */
    struct event_cb_args event_read_args = {.base       = base,
                                            .event_self = event_self_cbarg(),
                                            .data_processor = data_processor};

    /* EV_PERSIST allows reading unlimited data from user, or until the callback
    function runs event_del */
    event_read = event_new(base, main_sockfd, EV_READ | EV_WRITE | EV_PERSIST,
                           accept_cb, &event_read_args);
    catchExcp(event_read == NULL, "event_new: couldn't initialize read event",
              1);

    status = event_add(event_read, NULL);
    catchExcp(status == -1, "event_add: couldn't add read event",
              1); // no timeout

    status = event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);
    catchExcp(status == -1, "event_base_dispatch: couldn't start event loop",
              1);

    evutil_closesocket(main_sockfd);
    event_free(event_read);

    return 0;

err:
    return -1;
}

/** check if a function that returned `status` threw an error (Meaning it
returned `bad_status`)
 * @param status The actual value to check against.
 * @param bad_status `status` that triggers program to exit on failure.
 * @param err_msg Error message, prints to `stderr`.
 * @param bool_exit Whether to exit the program at failure.
*/
void catchExcp(int condition, const char *restrict err_msg, int action) {
    if ( condition ) {
        fprintf(stderr, "%s\n", err_msg);
        switch ( action ) {
            case 1:
                exit(1);
        }
    }
}

void accept_cb(evutil_socket_t sockfd, short flags, void *arg) {

    printf("listener\n");

    evutil_socket_t      incoming_sockfd;
    struct event_cb_args args = *(struct event_cb_args *)arg;
    struct event_base   *base = args.base;
    struct event        *self = args.event_self;
    struct event        *event_incoming;
    // sockaddr big enough for either IPv4 or IPv6
    struct sockaddr_storage *sockaddr =
        calloc(1, sizeof(struct sockaddr_storage));
    ev_socklen_t sockaddr_size = sizeof(struct sockaddr_storage);
    ev_ssize_t   nbytes        = 0;
    int          status;

    // sockfd is nonblocking but this function is only called when there's data
    // to read, so we expect no blocking on this call and the next recv() call
    incoming_sockfd =
        accept(sockfd, (struct sockaddr *)sockaddr, &sockaddr_size);

    if ( incoming_sockfd == EVUTIL_INVALID_SOCKET ) {
        fprintf(stderr, "accept: %s",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    evutil_make_socket_nonblocking(incoming_sockfd);

    event_incoming = event_new(base, incoming_sockfd, EV_READ, recv_cb, arg);
    catchExcp(event_incoming == NULL,
              "event_new: couldn't initialize accept event", 1);

    status = event_add(event_incoming, NULL);
    catchExcp(status == -1, "event_add: couldn't add accept event", 1);

    free(sockaddr);
}

/**
 * @brief Callback function to read data sent from client.
 *
 * After the connection is established (via `accept()` and the accept_cb()
 * callback function), the client may send data. This function receives the data
 * and closes the connection.
 * Signature matches the required signature for callback function in
 * documentation of `event_new()`.
 */
void recv_cb(evutil_socket_t sockfd, short flags, void *arg) {
    struct event_cb_args *args = (struct event_cb_args *)arg; // TODO: remove?
    struct event         *self = args->event_self;

    int   request_buffer_size = INIT_MAX_BUFFER_SIZE;
    char *incoming_buffer     = calloc(request_buffer_size, sizeof(char));

    catchExcp(incoming_buffer == NULL, "calloc: couldn't allocate buffer", 1);

    /** Receive and parse request line (method, path, HTTP version, headers) **/

    http_req   request;
    ev_ssize_t nbytes         = 0;
    ev_ssize_t bytes_parsed   = 0;
    ev_ssize_t bytes_recieved = 0;

    http_recv_and_parse_request(sockfd, incoming_buffer, request_buffer_size,
                                &request, &bytes_recieved, &bytes_parsed);

    incoming_buffer += bytes_parsed; // Advance request buf pointer,
                                     // should be pointing to start of
                                     // message content now

    // TODO: do stuff based on method type, receive rest of the content based on
    // content-length header

    /** Read request contents **/

    // should Content_Length value be used here, or be calculated from the
    // number of bytes received by recv()?
    ev_ssize_t http_content_len =
        atoi(http_get_header(request, "Content-Length")
                 ->value); // TODO: TRUSTING USER INPUT!!
    char *http_request_body = malloc(request->headers);

    http_recv_body(http_request_body);

    while () {
        total_bytes += nbytes;
        nbytes = recv(sockfd, incoming_buffer + total_bytes,
                      request_buffer_size - total_bytes, 0);
    }

    /**********************************
                Parsing data and responding
        ***********************************/

    int        response_buffer_size = INIT_MAX_BUFFER_SIZE;
    char      *response     = calloc(sizeof(char), response_buffer_size);
    ev_ssize_t response_len = response_buffer_size;
    ev_ssize_t bytes_sent   = 0;
    nbytes                  = 0;

    do {
        bytes_sent += nbytes;
        nbytes = send(sockfd, response, response_len, 0);
    } while ( bytes_sent < response_len && nbytes != SOCKET_ERROR );

    if ( nbytes == SOCKET_ERROR ) {
        fprintf(stderr, "send: %s\n",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    evutil_closesocket(sockfd);
    event_free(self);
}

ev_ssize_t http_recv_and_parse_request(evutil_socket_t sockfd, char *buffer,
                                       ev_ssize_t  buffer_len,
                                       http_req   *http_request,
                                       ev_ssize_t *bytes_received,
                                       ev_ssize_t *bytes_parsed) {

    ev_ssize_t nbytes             = 0;
    ev_ssize_t tot_bytes_received = 0;
    ev_ssize_t tot_bytes_parsed   = 0;

    while ( 1 ) {
        tot_bytes_received += nbytes;
        nbytes = recv(sockfd, buffer + tot_bytes_received,
                      buffer_len - tot_bytes_received, 0);

        if ( nbytes == SOCKET_ERROR ) {
            switch ( EVUTIL_SOCKET_ERROR() ) {
                case ECONNRESET:
                    // TODO: handle connection reset by client
                    break;
                default:
                    fprintf(
                        stderr, "recv: %s\n",
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
                    exit(1);
            }
        }

        // TODO: make sure bytes_read returns the TOTAL number of bytes read,
        // even if called a second time. If it returns the number of bytes read
        // for this iteration we need += instead of =
        tot_bytes_parsed =
            http_parse_request(&buffer, http_request, tot_bytes_parsed);

        switch ( tot_bytes_parsed ) {
            case -1:      // TODO: Bad request?
                break;
            case -2:      // Incomplete request
                continue; // continue receiving, go to outer do..while loop
            default:
                assert(tot_bytes_parsed > 0); // TODO: is this good practice? we
                                              // always expect bytes_read >= -2
                break;
        }

        nbytes = 0;
        break;
    }

    *bytes_received = tot_bytes_parsed;
    *bytes_parsed   = tot_bytes_parsed;

    return 0; // success
}

int http_recv_body() {}

int http_parse_request(char **buffer, ev_ssize_t request_len,
                       http_req *req_struct, ev_ssize_t bytes_read,
                       ev_ssize_t *buffer_bytes_read) {

    bytes_read = phr_parse_request(
        *buffer, request_len, &req_struct->method, &req_struct->method_len,
        &req_struct->path, &req_struct->path_len, &req_struct->minor_ver,
        req_struct->headers, &req_struct->num_headers, bytes_read);

    return bytes_read;
}

/**
 * @brief needs refactoring
 *
 * @param servinfo
 * @return int
 */
int local_socket_bind_listen(const char *restrict port) {
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

struct sockaddr *get_sockaddr(struct addrinfo *ai) {
    /* 	switch (ai->ai_family) {
                    // IPv4
                    case AF_INET:
                            return (struct sockaddr*) ((struct sockaddr_in*)
       ai->ai_addr)->sin_addr
            } */
    return NULL;
}
