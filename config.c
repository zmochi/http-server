#include "src/main.h"

int main() {
    config conf = {
        .ROOT_PATH = "/Users/orian/plearning/C_learning/HTTP",
        .PORT      = "25565",
        .SERVNAME  = "http1",
        .timeout   = 5,
    };

    init_server(conf);
}
