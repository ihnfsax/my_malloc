glibc_install=/home/athena/develop/glibc-2.25/64

C_SOURCE_FILE = $(wildcard *.c)

CXX_SOURCE_FILE = $(wildcard *.cpp) $(wildcard *.cc)

SOURCE_FILE = $(C_SOURCE_FILE) $(CXX_SOURCE_FILE)

CC = gcc

C++ = g++

LINK_FLAGS = -L "${glibc_install}/lib" -I "${glibc_install}/include" -Wl,-rpath="${glibc_install}/lib" -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux-x86-64.so.2"

C_FLAGS = $(LINK_FLAGS) -std=gnu11 -g3 -ggdb3 -Wall -pthread 

CXX_FLAGS = $(LINK_FLAGS) -std=c++11 -g3 -ggdb3 -Wall -pthread

BIN_PATH = ../../../bin

# 编译所有C、C++文件
all : c c++

# 只编译所有C语言文件
c :  $(basename $(C_SOURCE_FILE))

# # 只编译所有C++文件
c++ : $(basename $(CXX_SOURCE_FILE))


# # 指定具体某个文件进行编译
$(basename $(C_SOURCE_FILE)) : % : %.c
	$(CC) $< -o $(BIN_PATH)/$@ $(C_FLAGS)

# $(basename $(CXX_SOURCE_FILE)) : % : $(wildcard %.cpp) $(wildcard %.cc)
# 	$(C++) $< -o $@ $(CXX_FLAGS)

# 如果是多目标，-符号忽略编译错误，继续编译其他文件
define CPP_RULE
$1 : $$(wildcard $1.cpp) $$(wildcard $1.cc)
	-$$(C++) $$< -o $$@ $$(CXX_FLAGS)
endef

$(foreach e, $(basename $(CXX_SOURCE_FILE)), $(eval $(call CPP_RULE, $e)))

# 只显示成功删除的文件信息
.PHONY : clean
clean : 
	@-rm -vf $(basename $(SOURCE_FILE)) *.o
