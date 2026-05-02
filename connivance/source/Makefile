
CC = g++

FLAGS = -O2 -std=c++20 -no-pie -fno-stack-protector -D_FORTIFY_SOURCE=0 -s

LDFLAGS = $(FLAGS) -L. -lmbedcrypto
SRCFLAGS = $(FLAGS) -Iobf -Iinclude -MMD

SRC = $(shell find obf/ -type f -name "*.cpp")
OBJS = $(patsubst obf/%,build/%.o,$(SRC))

ASM = $(shell find files/ -type f -name "*.asm")

chal/main: $(OBJS) finish.py assembler.py $(ASM)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	python3 finish.py

build/%.o: obf/%
	mkdir -p $(dir $@)
	$(CC) $(SRCFLAGS) -c -o $@ $<

clean:
	rm -rf build
	rm -f chal/main

%.h:

-include $(OBJS:.o=.d)
