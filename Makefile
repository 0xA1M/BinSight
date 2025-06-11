.PHONY: all build run clean

all: build

build:
	cmake -S . -B build
	cmake --build build

run:
	@./build/binsight ./build/binsight

run32:
	@./build/binsight ~/Playground/C/main

clean:
	rm -rf build
