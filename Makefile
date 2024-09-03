# raw compilation command:
# clang `pkg-config --cflags --libs libevent` -Llibs -lpicohttpparser -o ./start_server src/headers.c src/http_utils.c src/main.c src/status_codes.c config.c

#LIBEVENT_LIB_FLAGS := `pkg-config --libs libevent`
LIBEVENT_C_FLAGS := `pkg-config --libs --cflags libevent`
LIB_FLAGS = -L$(LIB_DIR) -lpicohttpparser $(LIBEVENT_C_FLAGS)
SHARED_LIB_FILES = $(LIB_DIR)/libpicohttpparser.a
CFLAGS = $(LIB_FLAGS) $(OPT)

SRC_DIR = src
H_DIR = src
O_DIR = obj
LIB_DIR = libs

EXECUTABLE_NAME = ./start_server
MAIN_NAME = config.c
MAKE = make
CC = clang

# header file names with path relative to $(H_DIR)
_HDEPS = headers.h main.h http_utils.h status_codes.h http_limits.h parser.h event_loop.h
# c file names with path relative to $(SRC_DIR)
_CDEPS = headers.c main.c http_utils.c status_codes.c http_limits.c parser.c event_loop.c
HDEPS = $(patsubst %.h,$(H_DIR)/%.h,$(_HDEPS))
CDEPS = $(patsubst %.c,$(SRC_DIR)/%.c,$(_CDEPS))
OBJ = $(patsubst %.c,$(O_DIR)/%.o,$(_CDEPS))


main: OPT += -O3
main: all LIBS

debug: OPT += -g
debug: all LIBS

all: $(SHARED_LIB_FILES) $(OBJ) $(MAIN_NAME) 
	$(CC) $(CFLAGS) -o $(EXECUTABLE_NAME) $(OBJ) $(MAIN_NAME)

$(O_DIR)/%.o: $(SRC_DIR)/%.c $(H_DIR) # include all header dependencies since C files each include multiple .h files
	mkdir -p obj
	$(CC) $(CFLAGS) -c $< -o $@

$(MAIN_NAME): $(CDEPS) $(HDEPS)

test: all LIBS
	$(CC) $(CFLAGS) -g -o unit_tests $(OBJ) unit_tests.c

$(LIB_DIR)/%.a: LIBS
	$(MAKE) -C libs

