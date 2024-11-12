LIB_INCLUDE_FLAGS = `pkg-config --cflags libevent` -I$(LIB_DIR) 
LIB_LINK_FLAGS = `pkg-config --libs libevent` -L$(LIB_DIR) -lpicohttpparser 

# The following file is generated by the Makefile found in libs folder, which compiles picohttpparser (Make sure to clone this repo with submodules!)
CFLAGS = $(OPT) -I$(INCLUDE_DIR) -std=c23 -Wextra -Wall -Wconversion -Wsign-conversion

# project directories relative to project root
SRC_DIR = src
H_DIR = $(INCLUDE_DIR)/src
OBJ_DIR = obj
# library dir, contains a Makefile to build necessary libraries
LIB_DIR = libs
INCLUDE_DIR = .

EXECUTABLE_NAME = ./start_server
MAIN_NAME = config.c
MAKE = make
CC = clang

# header file names with path relative to $(H_DIR)
_HDEPS = headers.h server.h http_utils.h status_codes.h http_limits.h parser.h event_loop.h container_of.h list.h queue.h
# C file names with path relative to $(SRC_DIR)
_CDEPS = headers.c server.c http_utils.c status_codes.c http_limits.c parser.c event_loop.c response.c

HDEPS = $(patsubst %.h,$(H_DIR)/%.h,$(_HDEPS))
CDEPS = $(patsubst %.c,$(SRC_DIR)/%.c,$(_CDEPS))
OBJ = $(patsubst %.c,$(OBJ_DIR)/%.o,$(_CDEPS))


main: OPT += -O3
main: all 

ubsan: OPT+= -fno-omit-frame-pointer -fsanitize=undefined
ubsan: debug

debug: OPT += -g -Og -DDEBUG
debug: all 

all: LIBS $(OBJ) http.h # http.h is a user-exposed header
	$(CC) $(CFLAGS) $(LIB_LINK_FLAGS) -o $(EXECUTABLE_NAME) $(OBJ) $(MAIN_NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(HDEPS) | directories # include all header dependencies since C files each include multiple .h files
	$(CC) $(CFLAGS) $(LIB_INCLUDE_FLAGS) -xc -c $< -o $@

# create directories for build
directories:
	mkdir -p $(OBJ_DIR)

test: all LIBS
	$(CC) $(CFLAGS) -g -o unit_tests $(OBJ) unit_tests.c

LIBS:
	$(MAKE) -C $(LIB_DIR)

clean:
	rm -f $(OBJ)
	$(MAKE) -C $(LIB_DIR) clean

.PHONY: clean LIBS
