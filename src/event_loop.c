#include "event_loop.h"
#include "http_utils.h"

#include <stdlib.h>

/* libevent: */
#include <event2/event.h>

/* private structs, exposed to user by name only in header file */

/* a group of libevent events representing a single HTTP connection,
 * encompassing everything needed to handle an HTTP connection. This is an
 * opaque struct passed around by the end-user when using this the event loop
 * API */
struct conn_data {
    struct event_loop *ev_loop;
    socket_t           sockfd;
    struct timeval     timeout;
    struct event      *event_read;
    struct event      *event_write;
    struct event      *event_close_con;
    /* user callbacks */
    ev_callback_fn read_cb;
    ev_callback_fn write_cb;
    ev_callback_fn close_conn_cb;
    /* user argument to pass to all events callback functions */
    void *user_cb_arg;
};

struct event *add_event(struct event_base *base, socket_t socket,
                        enum ev_type ev_type, ev_callback_fn callback_fn,
                        const struct timeval *timeout, void *arg);

/**
 * @brief wrapper callback function, acting as a middle man between end-user's
 * close_conn_cb and libevent. (current) purpose is to convert libevent-specific
 * flags into flags defined by the event loop API and to prevent possible
 * surprising arguments being passed to end-user's callback function by
 * libevent.
 *
 * concern: performance impact? need to benchmark libevent directly
 * calling the end-user's callback instead of using wrapper callback.
 *
 * note:
 * if user passesd flags, they should be the flags defined in `enum ev_flags`
 *
 * @param socket socket of connection
 * @param flags libevent flags/API flags defined in `enum ev_flags`
 * @param arg `struct event_data` ptr of user event
 */
void _ev_close_conn_cb(socket_t socket, short flags, void *arg) {
    struct conn_data *conn_data = (struct conn_data *)arg;
    enum ev_flags     api_flags;

    switch ( flags ) {
        case EV_TIMEOUT:
            api_flags = TIMEOUT;
            break;
        case CLIENT_CON_CLOSE:
            api_flags = CLIENT_CON_CLOSE;
            break;
        case SERV_CON_CLOSE:
            api_flags = SERV_CON_CLOSE;
            break;
    }

    conn_data->close_conn_cb(socket, api_flags, conn_data->user_cb_arg);
}

/**
 * @brief see _ev_close_conn_cb documentation
 */
void _ev_write_cb(socket_t socket, short flags, void *arg) {
    struct conn_data *ev_data = (struct conn_data *)arg;

    ev_data->write_cb(socket, 0, ev_data->user_cb_arg);
}

/**
 * @brief see _ev_close_conn_cb documentation
 */
void _ev_read_cb(socket_t socket, short flags, void *arg) {
    struct conn_data *ev_data = (struct conn_data *)arg;
    ev_data->read_cb(socket, 0, ev_data->user_cb_arg);
}

int ev_init_loop(struct event_loop *ev_loop) {
    struct event_base *event_loop_base;
    struct event      *event_accept;
    socket_t           listen_sockfd = ev_loop->listen_sockfd;
    int                status;

    _VALIDATE_LOGIC(ev_loop->read_cb != NULL && ev_loop->write_cb != NULL &&
                        ev_loop->close_conn_cb != NULL &&
                        ev_loop->new_conn_cb != NULL,
                    "all callback functions in `struct event_loop` should be "
                    "set before calling ev_init_loop().")

    event_loop_base = event_base_new();
    catchExcp(event_loop_base == NULL, "Couldn't open event base.", 1);

    ev_loop->base = event_loop_base;

    /* event_accept is triggered when there's a new connection and calls
     * accept_cb
     *
     * passing event_loop_base as callback function argument here so new events
     * can be added to current even loop after new_conn_cb is called */
    event_accept = add_event(event_loop_base, listen_sockfd, EV_NEWCONN,
                             ev_loop->new_conn_cb, NULL, ev_loop);

    status = event_base_loop(event_loop_base, EVLOOP_NO_EXIT_ON_EMPTY);
    if ( status == -1 ) {
        LOG_ERR("event_base_loop: couldn't start event loop");
        exit(1);
    }

    event_free(event_accept);

    return 0;
}

/* for internal use */
typedef short libevent_flag_t;

struct conn_data *ev_add_conn(struct event_loop *ev_loop, socket_t socket,
                              void *cb_arg) {
    /* freed in ev_remove_event */
    struct conn_data *connection_data = calloc(1, sizeof(*connection_data));
    struct timeval   *client_timeout  = &ev_loop->default_timeout;

    ev_callback_fn read_cb = ev_loop->read_cb, write_cb = ev_loop->write_cb,
                   close_conn_cb = ev_loop->close_conn_cb,
                   new_conn_cb   = ev_loop->new_conn_cb;

    _VALIDATE_LOGIC(ev_loop->base != NULL,
                    "base field of `struct event_loop` should be set by "
                    "calling ev_init_loop() first.");
    _VALIDATE_LOGIC(ev_loop->default_timeout.tv_sec > 0 ||
                        ev_loop->default_timeout.tv_usec > 0,
                    "`struct event_loop` must have timeout > 0.");

    connection_data->ev_loop = ev_loop;

    /* set timeout to default timeout of events in this event loop */
    connection_data->timeout = *client_timeout;

    connection_data->read_cb       = read_cb;
    connection_data->write_cb      = write_cb;
    connection_data->close_conn_cb = close_conn_cb;
    connection_data->user_cb_arg   = cb_arg;

    /* add_event() simply exits on error, no need to check errors */
    connection_data->event_read = add_event(ev_loop->base, socket, EV_RECV,
                                            _ev_read_cb, NULL, connection_data);

    connection_data->event_write = add_event(
        ev_loop->base, socket, EV_SEND, _ev_write_cb, NULL, connection_data);

    connection_data->event_close_con =
        add_event(ev_loop->base, socket, EV_CLOSE, _ev_close_conn_cb,
                  client_timeout, connection_data);

    connection_data->sockfd = socket;

    return connection_data;
}

void ev_remove_conn(struct conn_data *conn_data) {
    event_free(conn_data->event_read);
    event_free(conn_data->event_write);
    event_free(conn_data->event_close_con);

    /* allocated in ev_add_conn */
    free(conn_data);
}

void event_wake(struct conn_data *ev_data, enum ev_type ev_type,
                enum ev_flags flags) {
    _VALIDATE_LOGIC(
        !(flags & (EV_TIMEOUT | EV_READ | EV_WRITE | EV_SIGNAL | EV_PERSIST |
                   EV_ET | EV_FINALIZE | EV_CLOSED)),
        "Passed flags %d that collide with event loop library flags.", flags)

    _VALIDATE_LOGIC(ev_type != EV_SEND && ev_type != EV_NEWCONN,
                    "EV_SEND and EV_NEWCONN are always active and should not "
                    "be manually woken up.");

    struct event *event_to_wake;

    switch ( ev_type ) {
        case EV_RECV:
            event_to_wake = ev_data->event_read;
            break;
        case EV_SEND:
            event_to_wake = ev_data->event_write;
            break;
        case EV_CLOSE:
            event_to_wake = ev_data->event_close_con;
            break;
        case EV_NEWCONN:
            LOGIC_ERR("EV_NEWCONN unsupported in event_wake()");
        default:
            LOGIC_ERR("Passed non-existent event type.");
    }

    event_active(event_to_wake, flags, 0);
}

struct event *add_event(struct event_base *base, socket_t socket,
                        enum ev_type ev_type, ev_callback_fn callback_fn,
                        const struct timeval *timeout, void *arg) {
    struct event   *ev;
    socket_t        sock = socket;
    libevent_flag_t libevent_flags;
    int             status;

    if ( ev_type == EV_NEWCONN )
        _VALIDATE_LOGIC(
            arg == NULL,
            "user `arg` in EV_NEWCONN event should always be null, the actual "
            "argument passed is set to be relevant `struct event_loop`");

    /* EV_PERSIST keeps the event active (always checking if there is
     * anything to send/read or new connections) instead of sending it to sleep
     * after a single wake-up */
    switch ( ev_type ) {
        case EV_RECV:
            libevent_flags = EV_READ | EV_PERSIST;
            break;
        case EV_SEND:
            libevent_flags = EV_WRITE | EV_PERSIST;
            break;
        case EV_CLOSE:
            libevent_flags = EV_TIMEOUT;
            sock           = -1;
            break;
        case EV_NEWCONN:
            /* EV_PERSIST keeps the event active (listening for new connections)
             * instead of sending it to sleep after a single wake-up */
            libevent_flags = EV_READ | EV_PERSIST;
            break;
        default:
            LOGIC_ERR("Passed non-existent event type.")
    }

    ev = event_new(base, sock, libevent_flags, callback_fn, arg);

    if ( !ev ) {
        LOG_ERR("event_new: error");
        exit(1);
    }

    /* technically EV_CLOSE shouldn't be added to pending events, but it's also
     * only woken */
    status = event_add(ev, timeout);

    if ( status == -1 ) {
        LOG_ERR("event_add: error");
        exit(1);
    }

    return ev;
}
