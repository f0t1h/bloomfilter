# Bloom Filter Makefile

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++23 -pedantic -Wall -Wextra -ftree-vectorize -mtune=native -march=native -O2 -pthread -lm

# Source files
BENCHMARK_SRC = simple_benchmark.cpp
HEADER = fbloom/bloom.h

# Default target
all: simple_benchmark

# Build benchmark
simple_benchmark: $(BENCHMARK_SRC) $(HEADER)
	$(CXX) $(CXXFLAGS) -o simple_benchmark $(BENCHMARK_SRC)


# Run benchmark
run: simple_benchmark
	./simple_benchmark


# Utility targets
clean:
	rm -f simple_benchmark *.o *.a *.so
	@echo "Clean completed"

help:
	@echo "=== Available Targets ==="
	@echo "  all          - Build benchmark (default)"
	@echo "  simple_benchmark - Build benchmark"
	@echo "  run          - Run benchmark"
	@echo "  clean        - Remove build artifacts"
	@echo "  help         - Show this help"

.PHONY: all simple_benchmark run clean help