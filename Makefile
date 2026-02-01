.PHONY: all build generate clean run-terminal run-file run-benchmark compare help

# Binary name
BINARY := monitor

# Default target
all: build

# Generate eBPF bytecode from C
generate:
	@echo "Generating eBPF bytecode..."
	go generate

# Build the Go binary
build: generate
	@echo "Building $(BINARY)..."
	go build -buildvcs=false -o $(BINARY)
	@echo "✓ Build complete: ./$(BINARY)"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY)
	rm -f monitor_bpfel.go monitor_bpfel.o
	rm -rf benchmark_results/
	@echo "✓ Clean complete"

# Quick test runs
run-terminal: build
	@echo "Running terminal mode (Ctrl+C to stop)..."
	sudo ./$(BINARY) terminal 10

run-file: build
	@echo "Running file mode (output to drops.txt)..."
	sudo ./$(BINARY) file 10 > drops.txt
	@echo "✓ Output written to drops.txt"
	@wc -l drops.txt

run-benchmark: build
	@echo "Running benchmark mode..."
	sudo ./$(BINARY) benchmark 10

# Run full comparison
compare: build
	@echo "Running full benchmark suite..."
	@chmod +x compare.sh
	sudo ./compare.sh 30

# Quick test (5 seconds each)
quick-test: build
	@echo "Running quick test (5 seconds per mode)..."
	@chmod +x compare.sh
	sudo ./compare.sh 5

# Install dependencies
deps:
	@echo "Installing Go dependencies..."
	go mod download
	@echo "✓ Dependencies installed"

# Check if running as root (required for eBPF)
check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: eBPF programs require root privileges"; \
		echo "Run with: sudo make <target>"; \
		exit 1; \
	fi

# Help message
help:
	@echo "eBPF Network Monitor - Makefile Commands"
	@echo "========================================"
	@echo ""
	@echo "Building:"
	@echo "  make build          - Build the binary (includes eBPF generation)"
	@echo "  make generate       - Generate eBPF bytecode only"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make deps           - Install Go dependencies"
	@echo ""
	@echo "Running (requires sudo):"
	@echo "  make run-terminal   - Quick 10-second terminal test"
	@echo "  make run-file       - Quick 10-second file output test"
	@echo "  make run-benchmark  - Quick 10-second benchmark"
	@echo ""
	@echo "Benchmarking:"
	@echo "  make compare        - Run full 30-second benchmark suite"
	@echo "  make quick-test     - Run quick 5-second benchmark suite"
	@echo ""
	@echo "Examples:"
	@echo "  make && sudo make run-terminal"
	@echo "  sudo make compare"
	@echo ""