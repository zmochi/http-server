const int BACKLOG                   = 64;
const int INIT_RECV_BUFFER_SIZE     = 256;
const int INIT_SEND_BUFFER_CAPACITY = (1 << 10); // 1KB
const int MAX_RECV_BUFFER_SIZE      = (1 << 30); // 1GB
const int MAX_SEND_BUFFER_SIZE      = MAX_RECV_BUFFER_SIZE;
const int SEND_REALLOC_MUL          = 2;
const int RECV_REALLOC_MUL          = 2;
