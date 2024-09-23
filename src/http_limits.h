#ifndef __HTTP_LIMITS_H
#define __HTTP_LIMITS_H

/* this is #define'd instead of being an int because in headers.h, this value is
 * used to declare the size of an array inside a struct which has to be a
 * constant (`extern const int` doesn't work for some reason) */
#define REQ_HEADER_VALUES_MAX_SIZE (1 << 12) /* 4KB */

extern const unsigned int BACKLOG;
extern const unsigned int INIT_RECV_BUFFER_SIZE;
extern const unsigned int INIT_SEND_BUFFER_CAPACITY;
extern const unsigned int URI_PATH_LEN_LIMIT;
extern const unsigned int MAX_RECV_BUFFER_SIZE;
extern const unsigned int MAX_SEND_BUFFER_SIZE;
extern const unsigned int SEND_REALLOC_MUL;
extern const unsigned int RECV_REALLOC_MUL;

#endif /* __HTTP_LIMITS_H */
