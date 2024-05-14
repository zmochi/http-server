#ifdef _WIN32
#include <winsock.h>
#else // Unix probably?
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define SOCKET_ERROR -1

#endif

#include "libs/headers.c"
#include "libs/picohttpparser.h"
#include <assert.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <limits.h>
#include <stdarg.h> // for vargs, is this Windows compatible?
#include <stdbool.h>

#define PORT             "25565"
#define BACKLOG          64
#define INIT_BUFFER_SIZE 256
#define MAX_NUM_HEADERS  100

struct event_metadata {
    struct event_base *base;
    void              *event_self;
};

struct connection_metadata {
    struct event_metadata *event;
    char                  *recv_buffer;
    char                  *send_buffer;
    size_t                 recv_buffer_size;
    size_t                 send_buffer_size;
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
int              http_parse_request(char **buffer, ev_ssize_t buffer_len,
                                    http_req *req_struct, ev_ssize_t bytes_read);
ev_ssize_t http_recv_and_parse_request(evutil_socket_t sockfd, char *buffer,
                                       ev_ssize_t  buffer_len,
                                       http_req   *http_request,
                                       ev_ssize_t *bytes_received,
                                       ev_ssize_t *bytes_parsed);

int init_server(const char *restrict port);

int main() { init_server("80"); }

int init_server(const char *restrict port) {
    struct event_base *base;
    evutil_socket_t    main_sockfd;
    int                status;
    struct event      *event_read;
    struct event      *event_write;

    base = event_base_new();
    catchExcp(base == NULL, "Couldn't open event base.", 1);

    main_sockfd = local_socket_bind_listen(port);

    /* event_self_cbarg uses magic to pass event_read as
        an argument to the event_new cb function */
    struct event_metadata event_read_args = {.base       = base,
                                             .event_self = event_self_cbarg()};

    /* EV_PERSIST allows reading unlimited data from user, or until the callback
    function runs event_del */
    event_read =
        event_new(base, main_sockfd, EV_READ | /* EV_WRITE |  */ EV_PERSIST,
                  accept_cb, &event_read_args);
    catchExcp(event_read == NULL, "event_new: couldn't initialize read event",
              1);

    status = event_add(event_read, NULL);
    catchExcp(status == -1, "event_add: couldn't add read event",
              1); // TODO: timeout

    status = event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);
    catchExcp(status == -1, "event_base_loop: couldn't start event loop", 1);

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

void accept_cb(evutil_socket_t sockfd, short flags, void *event_metadata) {
    struct event *event_read;
    struct event *event_write;

    // sockaddr big enough for either IPv4 or IPv6
    struct sockaddr_storage *sockaddr =
        calloc(1, sizeof(struct sockaddr_storage));
    ev_socklen_t sockaddr_size = sizeof(struct sockaddr_storage);

    evutil_socket_t incoming_sockfd;
    int             status;

    // Initializing connection metadata
    struct connection_metadata *con_data = (struct connection_metadata *)calloc(
        1, sizeof(struct connection_metadata));
    catchExcp(con_data == NULL, "calloc: couldn't allocate connection metadata",
              1);
    int request_buffer_size = INIT_BUFFER_SIZE;

    con_data->event            = (struct event_metadata *)event_metadata;
    con_data->recv_buffer      = calloc(request_buffer_size, sizeof(char));
    con_data->recv_buffer_size = request_buffer_size;
    catchExcp(con_data->recv_buffer == NULL, "calloc: couldn't allocate buffer",
              1);

    // sockfd is nonblocking but this function is only called when there's data
    // to read, so we expect no blocking on this call and the next recv() call
    incoming_sockfd =
        accept(sockfd, (struct sockaddr *)sockaddr, &sockaddr_size);

    if ( incoming_sockfd ==
         EVUTIL_INVALID_SOCKET ) { // TODO: make this work with catchExcp
        fprintf(stderr, "accept: %s",
                evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        exit(1);
    }

    evutil_make_socket_nonblocking(incoming_sockfd);

    event_read = event_new(con_data->event->base, incoming_sockfd, EV_READ,
                           recv_cb, con_data);
    catchExcp(event_read == NULL, "event_new: couldn't initialize accept event",
              1);

    event_write = event_new(con_data->event->base, incoming_sockfd, EV_WRITE,
                            send_cb, con_data);
    catchExcp(event_read == NULL, "event_new: couldn't initialize accept event",
              1);

    status = event_add(event_read, NULL);
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
    struct client_data {
        struct event *event;
        http_req     *request;
        char         *recv_buffer, *send_buffer;
        size_t        recv_buffer_len, send_buffer_len;
        ev_ssize_t    bytes_parsed, bytes_received;
        bool          headers_parsed, content_parsed;
    };

    if ( !arg->headers_parsed ) {
        // pass bytes_received/parsed to:
        http_recv_and_parse_request(); // and store the received data and
                                       // bytes_parsed in struct from `arg`, and
                                       // use the data
        if ( bad_request ) {
            // free the struct from `arg` and run event_del + free the event?
            http_respond(bad_request);
        } else if ( request_incomplete ) {
            // check if bytes_received == recv_buffer_len, if they are
            // then realloc recv_buffer to twice its size and update
            // recv_buffer_len
            // instead of realloc we can use a deamortized buffer (which
            // requires 3x space allocation)
            //
            // increase bytes_received/parsed
            return;
        }
    }
    arg->headers_parsed = true;

    // check all headers are ok/supported

    // iterate over all phr_header from parsing request and populate hashmap
    // with pointers to phr_headers
    struct phr_header headers[] = arg->request->headers;
    for ( int i = 0; i < arg->request->num_headers; i++ ) {
        struct hash_header *header =
            http_get_header(headers[i].name, headers[i].name_len);

        // TODO: Breaks on some machines, should define a macro for this that
        // uses the branchless version when needed
        // Assuming 2's complement, where -0 == 0 in bit presentation and
        // 0xFFFF.. represents -1.
        header->req_header =
            (struct phr_header *)((intptr_t)&headers[i] *
                                  (-(-((intptr_t)header) >>
                                     (sizeof(intptr_t) * CHAR_BIT - 1))));
        // this is the branchless version of:
        // if ( header != NULL ) { // Recognized header
        //     header->req_header = &headers[i];
        // } else {
        //     header->req_header = NULL;
        // }
    }

    http_recv_content(); // pass bytes_received here from the struct, this
                         // function should not call recv and only see if all
                         // the content has been sent (ends with \r\n\r\n), and
                         // set content_parsed.
                         // if not, update bytes_parsed and check if
                         // bytes_received == recv_buffer_len, then realloc
                         // accordingly and return

    // generate insert response into the send buffer in the struct
}

ev_ssize_t http_recv_and_parse_request(evutil_socket_t sockfd, char *buffer,
                                       ev_ssize_t  buffer_len,
                                       http_req   *http_request,
                                       ev_ssize_t *bytes_received,
                                       ev_ssize_t *bytes_parsed) {

    ev_ssize_t nbytes             = 0;
    ev_ssize_t tot_bytes_received = 0;
    ev_ssize_t tot_bytes_parsed   = 0;

    nbytes = recv(sockfd, buffer + tot_bytes_received,
                  buffer_len - tot_bytes_received, 0);

    if ( nbytes == SOCKET_ERROR ) {
        switch ( EVUTIL_SOCKET_ERROR() ) {
            case ECONNRESET:
            // TODO: handle connection reset by client
            case EWOULDBLOCK:
                // if ( tot_bytes_received == 0 ) {
                //     // No data at all
                //     goto exit;
                // }
                // TODO: data not received yet, but since the socket is
                // nonblocking we can't wait for it. Possible DOS attack if
                // we wait forever for the data, so implement timeout in
                // libevent

                // tot_bytes_received > 0, so we received and parsed some of
                // the request already.

            default:
                fprintf(stderr, "recv: %s\n",
                        evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
                exit(1);
        }
    }
    tot_bytes_received += nbytes;

    // http_parse_request (Or actually phr_parse_request that is called from
    // it) returns the *total* length of the HTTP request line + headers for
    // each call, so for each iteration we use = instead of +=
    tot_bytes_parsed =
        http_parse_request(&buffer, buffer_len, http_request, tot_bytes_parsed);

    switch ( tot_bytes_parsed ) {
        case -1:       // TODO: Bad request?
            return -1; // return -1 if request has invalid format
            break;
        case -2:       // Incomplete request

        default:
            assert(tot_bytes_parsed > 0); // TODO: is this good practice? we
            // always expect bytes_read >= -2
            break;
    }

    *bytes_received = tot_bytes_received;
    *bytes_parsed   = tot_bytes_parsed;

    return 0; // success
}

int http_recv_body() {}

int http_parse_request(char **buffer, ev_ssize_t buffer_len,
                       http_req *req_struct, ev_ssize_t bytes_read) {

    bytes_read = phr_parse_request(
        *buffer, buffer_len, &req_struct->method, &req_struct->method_len,
        &req_struct->path, &req_struct->path_len, &req_struct->minor_ver,
        req_struct->headers, &req_struct->num_headers, bytes_read);

    // TODO: maybe move method validation and others here, to spare receiving
    // and parsing the entire HTTP message before responding?

    return bytes_read;
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

struct sockaddr *get_sockaddr(struct addrinfo *ai) {
    /* 	switch (ai->ai_family) {
                    // IPv4
                    case AF_INET:
                            return (struct sockaddr*) ((struct sockaddr_in*)
       ai->ai_addr)->sin_addr
            } */
    return NULL;
}
