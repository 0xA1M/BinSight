.PHONY: all build rebuild run run32 test check clean distclean release

all: build

CMAKE_BUILD_TYPE ?= Debug

build:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)
	cmake --build build

# Force a clean rebuild
rebuild: distclean build

# Run the main program with itself as input
run: build
	./build/binsight ./build/binsight

# Run against a 32-bit sample file
run32: build
	./build/binsight ~/Playground/32/main

test: build
	cd build && ctest --output-on-failure

# Alias for test
check: test

# Clean only build artifacts
clean:
	$(MAKE) -C build clean

# Remove build directory
distclean:
	rm -rf build

# Release build (optimized binary)
release:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build --config Release
