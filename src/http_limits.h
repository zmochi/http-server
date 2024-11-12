#ifndef __HTTP_LIMITS_H
#define __HTTP_LIMITS_H

constexpr unsigned int REQ_HEADER_VALUES_MAX_SIZE = (1 << 12); /* 4KB */

constexpr unsigned int BACKLOG = 64;
constexpr unsigned int INIT_RECV_BUFFER_SIZE = 256;
constexpr unsigned int INIT_SEND_BUFFER_CAPACITY = (1 << 10); // 1KB
/* a buffer containing the path of request is allocated for each request */
constexpr unsigned int URI_PATH_LEN_LIMIT = 128;
constexpr unsigned int MAX_RECV_BUFFER_SIZE = (1 << 13); // 8KB
constexpr unsigned int MAX_SEND_BUFFER_SIZE = MAX_RECV_BUFFER_SIZE;
constexpr unsigned int SEND_REALLOC_MUL = 2;
constexpr unsigned int RECV_REALLOC_MUL = 2;

#endif /* __HTTP_LIMITS_H */
