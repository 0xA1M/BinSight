.PHONY: all build rebuild run run32 test check clean distclean release fuzz-build fuzz fuzz-clean

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

# Fuzzing related targets
FUZZER := afl-fuzz
FUZZ_INPUT_DIR := fuzz/in
FUZZ_OUTPUT_DIR := fuzz/out
FUZZ_TARGET_BINARY := build/binsight

fuzz-build: distclean
	export CC=afl-clang-fast && \
	export CXX=afl-clang-fast++ && \
	export AFL_SKIP_CPUFREQ=1 && \
	cmake -S . -B build -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) && \
	cmake --build build

fuzz: fuzz-build
	mkdir -p $(FUZZ_INPUT_DIR)
	$(FUZZER) -i $(FUZZ_INPUT_DIR) -o $(FUZZ_OUTPUT_DIR) -- ./$(FUZZ_TARGET_BINARY) @@

fuzz-clean:
	rm -rf $(FUZZ_OUTPUT_DIR)
