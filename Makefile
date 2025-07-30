.PHONY: all build run clean

all: build

build:
	cmake -S . -B build
	cmake --build build

run: build
	@./build/binsight ./build/binsight

run32: build
	@./build/binsight ~/Playground/32/main

clean:
	rm -rf build
