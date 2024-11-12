# Makefile for generating dynamic library. This is run when the Makefile from the top directory is executed.

CC = clang
ARCHIVER = ar rcs
PICO_SRC_DIR = ./picohttpparser
PICO_SRC = $(PICO_SRC_DIR)/picohttpparser.c
PICO_OBJ = ./picohttpparser.o
PICO_LIB = libpicohttpparser.a

all: static_lib

static_lib: $(PICO_OBJ)
	$(ARCHIVER) $(PICO_LIB) $(PICO_OBJ)

$(PICO_OBJ): $(PICO_SRC)
	$(CC) -c $(PICO_SRC) -o $(PICO_OBJ)

clean:
	rm -f $(PICO_OBJ) $(PICO_LIB)

.PHONY: clean
