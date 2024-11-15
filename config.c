#include <src/server.h>
#include <string.h>

http_res handler(http_req *request) {
    http_res response = {.status_code = Not_Implemented,
                         .message = NULL,
                         .message_len = 0,
                         .headers_arr = NULL,
                         .num_headers = 0,
                         .res_flags = 0};
    return response;
}

int main() {
    config conf = {
        .ROOT_PATH = "/Users/orian/plearning/C_learning/HTTP",
        .PORT = "25565",
        .SERVNAME = "http1",
        .timeout = (struct timeval){.tv_sec = 99999999, .tv_usec = 0},
        .handler = handler,
    };

    init_server(conf);
}
