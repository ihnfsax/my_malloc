BIN_PATH = ../../../bin

C_FLAGS = -lm -pthread -std=gnu11 -O3 -Wall -DNO_HEAP_TRIM

MYMALLOC_INC = ../../my_malloc

GLIBC_TEST_FILES = $(wildcard ./glibc_benchtest/*.c)

MYMALLOC_TEST_FILES = $(wildcard ./my_malloc_benchtest/*.c)

all : glibc my_malloc

glibc : $(basename $(GLIBC_TEST_FILES))

my_malloc: $(basename $(MYMALLOC_TEST_FILES))

$(basename $(GLIBC_TEST_FILES)) : % : %.c
	-mkdir -p $(BIN_PATH)/glibc_benchtest
	gcc $< -o $(BIN_PATH)/glibc_benchtest/$(shell basename $@) $(C_FLAGS)

$(basename $(MYMALLOC_TEST_FILES)) : % : %.c
	-mkdir -p $(BIN_PATH)/my_malloc_benchtest
	gcc ../../my_malloc/my_malloc.c $< -o $(BIN_PATH)/my_malloc_benchtest/$(shell basename $@) $(C_FLAGS) -I$(MYMALLOC_INC)
