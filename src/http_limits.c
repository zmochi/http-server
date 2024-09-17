const int BACKLOG = 64;
const int INIT_RECV_BUFFER_SIZE = 256;
const int INIT_SEND_BUFFER_CAPACITY = (1 << 10); // 1KB
/* a buffer containing the path of request is allocated for each request */
const int INIT_PATH_BUFFER_SIZE = 128;
const int MAX_RECV_BUFFER_SIZE = (1 << 13); // 8KB
const int MAX_SEND_BUFFER_SIZE = MAX_RECV_BUFFER_SIZE;
const int SEND_REALLOC_MUL = 2;
const int RECV_REALLOC_MUL = 2;
