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

DEPS = headers main http_utils status_codes
EXECUTABLE_NAME = ./start_server
MAIN_NAME = config.c
MAKE = make
CC = clang

HDEPS = $(patsubst %,$(H_DIR)/%.h,$(DEPS))
CDEPS = $(patsubst %,$(SRC_DIR)/%.c,$(DEPS))
OBJ = $(patsubst %,$(O_DIR)/%.o,$(DEPS))


main: OPT += -O3
main: all LIBS

debug: OPT += -g
debug: all LIBS

all: $(SHARED_LIB_FILES) $(OBJ) $(MAIN_NAME) 
	$(CC) $(CFLAGS) -o $(EXECUTABLE_NAME) $(OBJ) $(MAIN_NAME)

$(O_DIR)/%.o: $(SRC_DIR)/%.c $(HDEPS) # include all header dependencies since C files each include multiple .h files
	$(CC) $(CFLAGS) -c $< -o $@

$(MAIN_NAME): $(CDEPS) $(HDEPS)


$(LIB_DIR)/%.a: LIBS
	$(MAKE) -C libs

