CXX_FLAGS = -O3 -Wall -std=gnu11 -DHEAP_INFO

INC = ../../my_malloc

BIN_PATH = ../../../bin

C_SOURCE_FILE = simple_test.c $(INC)/my_malloc.c

C_HEADER_FILE = $(INC)/my_malloc.h

all : $(C_SOURCE_FILE) $(C_HEADER_FILE)
	gcc -I$(INC) $(CXX_FLAGS) $(C_SOURCE_FILE) -o $(BIN_PATH)/simple_test

.PHONY : clean
clean: 
	rm -f $(BIN_PATH)/simple_test