# Bloom Filter Makefile
# C89 compliant bloom filter implementation

# Compiler settings
CC = gcc
CFLAGS = -std=c99 -pedantic -Wall -Wextra -O2
CFLAGS_DEBUG = -std=c99 -pedantic -Wall -Wextra -g -DDEBUG
CFLAGS_STRICT = -std=c99 -pedantic -Wall -Wextra -Werror -O2
LDFLAGS = -lm

# Directories
SRCDIR = .
INCDIR = fbloom
BUILDDIR = build
TESTDIR = tests

# Source files
TEST_SRC = test.c
HEADER = $(INCDIR)/bloom.h

# Target executables
TEST_TARGET = test
TEST_DEBUG_TARGET = test_debug
TEST_STRICT_TARGET = test_strict

# Default target
all: $(TEST_TARGET)

# Create build directory
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Main test executable
$(TEST_TARGET): $(TEST_SRC) $(HEADER)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TEST_TARGET) $(TEST_SRC)

# Debug build
debug: $(TEST_DEBUG_TARGET)

$(TEST_DEBUG_TARGET): $(TEST_SRC) $(HEADER)
	$(CC) $(CFLAGS_DEBUG) $(LDFLAGS) -o $(TEST_DEBUG_TARGET) $(TEST_SRC)

# Strict compilation (warnings as errors)
strict: $(TEST_STRICT_TARGET)

$(TEST_STRICT_TARGET): $(TEST_SRC) $(HEADER)
	$(CC) $(CFLAGS_STRICT) $(LDFLAGS) -o $(TEST_STRICT_TARGET) $(TEST_SRC)

# Run tests
run-test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Build 64-bit test
test64: test64.c $(HEADER)
	$(CC) $(CFLAGS) $(LIBS) -o test64 test64.c

# Build C++ test
test-cpp: test.cpp $(HEADER)
	g++ -std=c++17 -pedantic -Wall -Wextra -O2 -lm -o test-cpp test.cpp

# Run 64-bit tests
run-test64: test64
	./test64

# Run C++ tests
run-test-cpp: test-cpp
	./test-cpp

# Run all tests (32-bit, 64-bit, and C++)
run-all-tests: $(TEST_TARGET) test64 test-cpp
	@echo "Running 32-bit tests..."
	./$(TEST_TARGET)
	@echo ""
	@echo "Running 64-bit tests..."
	./test64
	@echo ""
	@echo "Running C++ tests..."
	./test-cpp

# Run debug tests
test-debug: $(TEST_DEBUG_TARGET)
	./$(TEST_DEBUG_TARGET)

# Run strict tests
test-strict: $(TEST_STRICT_TARGET)
	./$(TEST_STRICT_TARGET)

# Check C99 compliance
c99-check: $(TEST_SRC) $(HEADER)
	$(CC) -std=c99 -pedantic -Wall -Wextra -Werror -fsyntax-only $(TEST_SRC)
	@echo "C99 compliance check passed!"

# Memory check with valgrind (if available)
memcheck: $(TEST_TARGET)
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./$(TEST_TARGET); \
	else \
		echo "Valgrind not found, skipping memory check"; \
		./$(TEST_TARGET); \
	fi

# Static analysis with cppcheck (if available)
static-analysis:
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --std=c89 --suppress=missingIncludeSystem $(TEST_SRC) $(HEADER); \
	else \
		echo "cppcheck not found, skipping static analysis"; \
	fi

# Format code (if clang-format is available)
format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i -style="{BasedOnStyle: LLVM, IndentWidth: 4, UseTab: Never}" $(TEST_SRC) $(HEADER); \
		echo "Code formatted successfully"; \
	else \
		echo "clang-format not found, skipping formatting"; \
	fi

# Create a simple benchmark
benchmark: $(TEST_TARGET)
	@echo "Running bloom filter benchmark..."
	@time ./$(TEST_TARGET) > /dev/null
	@echo "Benchmark completed"

# Install header (copy to /usr/local/include)
install: $(HEADER)
	@if [ "$(shell id -u)" = "0" ]; then \
		cp $(HEADER) /usr/local/include/; \
		echo "Header installed to /usr/local/include/"; \
	else \
		echo "Run 'sudo make install' to install header system-wide"; \
	fi

# Uninstall header
uninstall:
	@if [ "$(shell id -u)" = "0" ]; then \
		rm -f /usr/local/include/bloom.h; \
		echo "Header uninstalled from /usr/local/include/"; \
	else \
		echo "Run 'sudo make uninstall' to uninstall header system-wide"; \
	fi

# Create distribution package
dist: clean
	@mkdir -p bloom-filter-dist
	@cp $(HEADER) bloom-filter-dist/
	@cp $(TEST_SRC) bloom-filter-dist/
	@cp Makefile bloom-filter-dist/
	@cp README.md bloom-filter-dist/ 2>/dev/null || echo "README.md not found, skipping"
	@cp LICENSE bloom-filter-dist/ 2>/dev/null || echo "LICENSE not found, skipping"
	@tar -czf bloom-filter.tar.gz bloom-filter-dist/
	@rm -rf bloom-filter-dist/
	@echo "Distribution package created: bloom-filter.tar.gz"

# Show compiler and system info
info:
	@echo "=== Build Information ==="
	@echo "Compiler: $(CC)"
	@echo "C Flags: $(CFLAGS)"
	@echo "LD Flags: $(LDFLAGS)"
	@echo "System: $(shell uname -s)"
	@echo "Architecture: $(shell uname -m)"
	@$(CC) --version | head -1
	@echo ""
	@echo "=== Available Targets ==="
	@echo "  all          - Build test executable (default)"
	@echo "  debug        - Build with debug flags"
	@echo "  strict       - Build with warnings as errors"
	@echo "  run-test     - Run 32-bit tests"
	@echo "  run-test64   - Run 64-bit tests"
	@echo "  run-test-cpp - Run C++ tests"
	@echo "  run-all-tests - Run 32-bit, 64-bit, and C++ tests"
	@echo "  test-debug   - Run debug tests"
	@echo "  test-strict  - Run strict tests"
	@echo "  c99-check    - Check C99 compliance"
	@echo "  memcheck     - Run with memory checking (requires valgrind)"
	@echo "  static-analysis - Run static analysis (requires cppcheck)"
	@echo "  format       - Format code (requires clang-format)"
	@echo "  benchmark    - Run simple benchmark"
	@echo "  install      - Install header system-wide"
	@echo "  uninstall    - Uninstall header"
	@echo "  dist         - Create distribution package"
	@echo "  clean        - Remove build artifacts"
	@echo "  help         - Show this help"

# Help target
help: info

# Clean build artifacts
clean:
	rm -f $(TEST_TARGET) $(TEST_DEBUG_TARGET) $(TEST_STRICT_TARGET) test64 test-cpp
	rm -f *.o *.a *.so
	rm -f *.tar.gz
	rm -rf $(BUILDDIR)
	rm -rf bloom-filter-dist/
	@echo "Clean completed"

# Phony targets
.PHONY: all debug strict run-test run-test64 run-test-cpp run-all-tests test64 test-cpp test-debug test-strict c99-check memcheck static-analysis format benchmark install uninstall dist info help clean
