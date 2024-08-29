#include "main.h"

#define MAX_BUF_SIZE_EXCEEDED 2

struct addrinfo *get_local_addrinfo(const char *port);
int              local_socket_bind_listen(const char *port);

/**
 * @brief Loads entire contents of file specified by filepath into `buf`.
 *
 * @param buf Buffer to write to
 * @param buflen Maximum amount of space available in `buf`
 * @param filepath Path of file to write from
 * @return 0 on success, -1 on error, or the number of
 * bytes written to buffer if EOF was not reached.
 */
ev_ssize_t  load_file_to_buf(FILE *file, char *buf, size_t buflen,
                             size_t *last_len);
int         http_extract_validate_header(const char *header_name,
                                         size_t      header_name_len,
                                         const char *expected_value,
                                         size_t      expected_value_len);
int         http_extract_content_length(size_t *content_length_storage,
                                        size_t  max_content_length);
int         handler_buf_realloc(char **buf, size_t *bufsize, size_t max_size,
                                ev_ssize_t new_size);
const char *stringify_statuscode(http_status_code status_code);
bool        is_integer(const char str[], int str_len);
int         strftime_gmtformat(char *buf, size_t buflen);
void        catchExcp(int condition, const char *err_msg, int action);
