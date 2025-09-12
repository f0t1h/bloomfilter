# Bloom Filter Makefile

# Compiler settings
CXX = g++
CXXSTD = -std=c++23
CXXWARN = -pedantic -Wall -Wextra
CXXOPT = -O3 -ftree-vectorize -mtune=native -march=native
CXXFLAGS = $(CXXSTD) $(CXXWARN) $(CXXOPT) -pthread -lm

# Directories
SRC_DIR = .
FBLOM_DIR = fbloom
PLOT_DIR = benchmark_plots

# Source files
BENCHMARK_SRC = simple_benchmark.cpp

# Header files
HEADERS = $(FBLOM_DIR)/bloom.h $(FBLOM_DIR)/gloom.h $(FBLOM_DIR)/parallel_bloom.h

# Executables
BENCHMARK_EXE = simple_benchmark

# Default target
all: $(BENCHMARK_EXE)

# Build benchmark
$(BENCHMARK_EXE): $(BENCHMARK_SRC) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o $@ $<

# Alias target for convenience
simple_benchmark: $(BENCHMARK_EXE)

# Run targets
run: $(BENCHMARK_EXE)
	@echo "Running benchmark..."
	./$(BENCHMARK_EXE)

# Visualization targets
viz: viz_benchmark.py benchmark_results.tsv
	@echo "Generating visualizations for benchmark_results.tsv..."
	@mkdir -p $(PLOT_DIR)
	@source fbloom_py_env/bin/activate && python3 viz_benchmark.py benchmark_results.tsv

# Utility targets
clean:
	@echo "Cleaning build artifacts and generated files..."
	rm -f $(BENCHMARK_EXE) *.o *.a *.so
	rm -rf $(PLOT_DIR)
	@echo "Clean completed"

# Development targets
debug: CXXFLAGS = $(CXXSTD) $(CXXWARN) -g -O0 -pthread -lm
debug: $(BENCHMARK_EXE)
	@echo "Debug build completed"

# Help target
help:
	@echo "=== Bloom Filter Makefile ==="
	@echo ""
	@echo "Build Targets:"
	@echo "  all              - Build benchmark (default)"
	@echo "  simple_benchmark - Build benchmark"
	@echo "  debug            - Build debug version with symbols"
	@echo ""
	@echo "Run Targets:"
	@echo "  run              - Run benchmark"
	@echo ""
	@echo "Visualization Targets:"
	@echo "  viz              - Generate plots for benchmark results"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean            - Remove all build artifacts and plots"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Compiler: $(CXX)"
	@echo "Flags: $(CXXFLAGS)"

.PHONY: all simple_benchmark debug run viz clean help