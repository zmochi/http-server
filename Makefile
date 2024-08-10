# raw compilation command:
# clang `pkg-config --cflags --libs libevent` -Llibs -lpicohttpparser -o ./start_server src/headers.c src/http_utils.c src/main.c src/status_codes.c config.c

LIBEVENT_LIB_FLAGS := `pkg-config --libs libevent`
LIBEVENT_C_FLAGS := `pkg-config --cflags libevent`
LIB_DIR := libs
STATIC_LIBS_FLAGS := -L$(LIB_DIR) -lpicohttpparser
SRC_DIR := src
H_DIR := src
O_DIR := obj
DEPS = headers main http_utils status_codes
HDEPS = $(patsubst %,$(H_DIR)/%.h,$(DEPS))
CDEPS = $(patsubst %,$(SRC_DIR)/%.c,$(DEPS))
OBJ = $(patsubst %,$(O_DIR)/%.o,$(DEPS))
EXECUTABLE_NAME := ./start_server
MAIN_NAME = config.c
CFLAGS = $(LIBEVENT_LIB_FLAGS) $(LIBEVENT_C_FLAGS) $(STATIC_LIBS_FLAGS) $(OPT)

CC = clang

main: OPT += -O3
main: all

debug: OPT += -g
debug: all

all: $(OBJ) $(MAIN_NAME)
	$(CC) $(CFLAGS) -o $(EXECUTABLE_NAME) $(OBJ) $(MAIN_NAME)

$(O_DIR)/%.o: $(SRC_DIR)/%.c $(HDEPS) # include all header dependencies since C files each include multiple .h files
	$(CC) $(LIBEVENT_C_FLAGS) $(OPT) -c -o $@ $<

$(MAIN_NAME): $(CDEPS) $(HDEPS)

