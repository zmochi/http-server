const unsigned int BACKLOG = 64;
const unsigned int INIT_RECV_BUFFER_SIZE = 256;
const unsigned int INIT_SEND_BUFFER_CAPACITY = (1 << 10); // 1KB
/* a buffer containing the path of request is allocated for each request */
const unsigned int URI_PATH_LEN_LIMIT = 128;
const unsigned int MAX_RECV_BUFFER_SIZE = (1 << 13); // 8KB
const unsigned int MAX_SEND_BUFFER_SIZE = MAX_RECV_BUFFER_SIZE;
const unsigned int SEND_REALLOC_MUL = 2;
const unsigned int RECV_REALLOC_MUL = 2;
