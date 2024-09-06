/* wrapper API around libevent's event loop for HTTP server needs */

/* for struct timeval */
#include <sys/time.h>
/* for CHAR_BIT */
#include <limits.h>
/* for cross-platform socket type evutil_socket_t */
#include <event2/util.h>

#ifndef __EVENT_LOOP_H
#define __EVENT_LOOP_H

typedef evutil_socket_t socket_t;

typedef void (*ev_callback_fn)(socket_t socket, int flags, void *arg);

/* flags to pass to libevent when calling event_new, for each possible type of
 * event relevant for the HTTP server */
enum ev_type {
    EV_RECV,
    EV_SEND,
    EV_CLOSE,
    EV_NEWCONN,
};

#define SET_LEFTMOST_SHORT_BIT(bit) (1 << (CHAR_BIT * sizeof(short) - bit - 1))
/* flags that an event callback can receive, must be set from left otherwise
 * they collide with event loop library flags */
enum ev_flags {
    /* enums are guaranteed to have max size of int, bigger than short */
    TIMEOUT = SET_LEFTMOST_SHORT_BIT(0), /* should not be passed manually. this
                is an event loop indication of timeout */
    SERV_CON_CLOSE   = SET_LEFTMOST_SHORT_BIT(1),
    CLIENT_CON_CLOSE = SET_LEFTMOST_SHORT_BIT(2),
};

/* private structs, end-user should only pass from/to the wrapper's methods */
struct event_base;
/* each conn_data encompasses 3 events, an `event group`: read, write and close
 * connection (close connection must be triggered manually with event_wake() or
 * timed out to trigger) */
struct conn_data;

struct event_loop {
    /* field for internal use, set by ev_init_loop() */
    struct event_base *base;
    socket_t           listen_sockfd;
    struct timeval     default_timeout;
    ev_callback_fn     read_cb;
    ev_callback_fn     write_cb;
    ev_callback_fn     close_conn_cb;
    /* @arg in new_conn_cb will always be the associated struct event_loop*
     * passed in ev_init_loop */
    ev_callback_fn new_conn_cb;
};

/**
 * @brief initializes an event loop
 *
 * @param ev allocated `struct event_loop` to initialize
 * @return 0 on success, 1 on failure
 */
int ev_init_loop(struct event_loop *ev);

/**
 * @brief adds a new connection (read, write and close connection events
 * associated with @socket) to an event loop @ev_base and schedules read, write,
 * close events on socket
 * @ev_socket
 *
 * @param ev_loop base to add events to
 * @param socket socket for the events to monitor
 * @param cb_arg argument to pass to callbacks read/write/close connection
 * @returns an opaque struct of the added connection
 */
struct conn_data *ev_add_conn(struct event_loop *ev_loop, socket_t socket,
                              void *cb_arg);

/**
 * @brief removes event (and its read, write and close events) @ev from its
 * event loop. closes the associated socket.
 *
 * @param conn connection to remove, that was returned by ev_add_conn()
 */
void ev_remove_conn(struct conn_data *conn);

/**
 * @brief schedules an event to run in the event loop
 *
 * @param conn connection to schedule the event on
 * @param ev_type type of event, from `enum ev_type`
 * @param flags flags from `enum ev_flags` to pass to woken event
 */
void event_wake(struct conn_data *conn, enum ev_type ev_type,
                enum ev_flags flags);

#endif /* __EVENT_LOOP_H */
