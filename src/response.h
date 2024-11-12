#ifndef __RESPONSE_H
#define __RESPONSE_H

#include <http.h>
#include <src/http_limits.h>
#include <src/http_utils.h>
#include <src/queue.h>
#include <src/send_queue.h>
#include <src/status_codes.h>

#define CRLF     "\r\n"
#define CRLF_LEN (2)

/**
 * @brief formats response into provided struct send_buffer, adds Content-Length
 * header if message exists
 *
 * after this functions returns, it is safe to free all data related to
 * @response and @response itself.
 * if either response->message is NULL or response->message_len is 0, no content
 * is sent with request
 *
 * @param send_buf buffer to format response into
 * @param response response to format
 * @param server_name name of server in formatted response
 * @return 0 on success, 1 on general failure and 2 if response is too large
 */
int format_response(struct buffer *send_buf, http_res *response,
                    const char *server_name);

#endif /* __RESPONSE_H */
