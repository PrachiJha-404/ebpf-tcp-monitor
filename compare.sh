#!/bin/bash

# eBPF Network Monitor Benchmark Suite
# Compares terminal, file, and benchmark modes

set -e

DURATION=${1:-30}  # Default 30 seconds
BINARY="./monitor"
OUTPUT_DIR="benchmark_results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           eBPF Network Monitor Benchmark Suite                       ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║ Duration per test: ${DURATION} seconds                                        ║${NC}"
echo -e "${BLUE}║ Total runtime: ~$((DURATION * 3)) seconds                                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
echo

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Error: Binary not found at $BINARY${NC}"
    echo "Run 'go generate && go build' first"
    exit 1
fi

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (eBPF requirement)${NC}"
    echo "Run: sudo $0"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${GREEN}Starting benchmark suite...${NC}\n"

# ============================================================================
# TEST 1: Terminal Mode
# ============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}TEST 1: Terminal Mode (slowest, limited by TTY)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

TERMINAL_LOG="$OUTPUT_DIR/terminal_${TIMESTAMP}.log"
$BINARY terminal $DURATION > "$TERMINAL_LOG" 2>&1

echo -e "${GREEN}✓ Terminal test complete${NC}"
echo -e "  Output saved to: $TERMINAL_LOG\n"
sleep 2

# ============================================================================
# TEST 2: File Mode (via redirect)
# ============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}TEST 2: File Mode (buffered I/O to disk)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

FILE_OUTPUT="$OUTPUT_DIR/drops_${TIMESTAMP}.txt"
FILE_LOG="$OUTPUT_DIR/file_${TIMESTAMP}.log"
$BINARY file $DURATION > "$FILE_OUTPUT" 2> "$FILE_LOG"

echo -e "${GREEN}✓ File test complete${NC}"
echo -e "  Output saved to: $FILE_OUTPUT"
echo -e "  Log saved to: $FILE_LOG\n"
sleep 2

# ============================================================================
# TEST 3: Benchmark Mode
# ============================================================================
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}TEST 3: Benchmark Mode (no I/O, pure counting)${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

BENCHMARK_LOG="$OUTPUT_DIR/benchmark_${TIMESTAMP}.log"
$BINARY benchmark $DURATION 2>&1 | tee "$BENCHMARK_LOG"

echo -e "${GREEN}✓ Benchmark test complete${NC}"
echo -e "  Log saved to: $BENCHMARK_LOG\n"

# ============================================================================
# SUMMARY
# ============================================================================
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                         BENCHMARK SUMMARY                            ║${NC}"
echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"

# Extract throughput from logs
extract_throughput() {
    grep "Throughput:" "$1" | awk '{print $2}'
}

TERMINAL_RATE=$(extract_throughput "$TERMINAL_LOG")
FILE_RATE=$(extract_throughput "$FILE_LOG")
BENCHMARK_RATE=$(extract_throughput "$BENCHMARK_LOG")

printf "${BLUE}║${NC} %-20s ${GREEN}%10s${NC} events/sec                              ${BLUE}║${NC}\n" "Terminal:" "$TERMINAL_RATE"
printf "${BLUE}║${NC} %-20s ${GREEN}%10s${NC} events/sec                              ${BLUE}║${NC}\n" "File (redirect):" "$FILE_RATE"
printf "${BLUE}║${NC} %-20s ${GREEN}%10s${NC} events/sec                              ${BLUE}║${NC}\n" "Benchmark:" "$BENCHMARK_RATE"

echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"

# Calculate speedups
if [ -n "$TERMINAL_RATE" ] && [ -n "$FILE_RATE" ]; then
    SPEEDUP=$(echo "scale=2; $FILE_RATE / $TERMINAL_RATE" | bc)
    echo -e "${BLUE}║${NC} File vs Terminal:   ${YELLOW}${SPEEDUP}x faster${NC}                                    ${BLUE}║${NC}"
fi

if [ -n "$TERMINAL_RATE" ] && [ -n "$BENCHMARK_RATE" ]; then
    SPEEDUP=$(echo "scale=2; $BENCHMARK_RATE / $TERMINAL_RATE" | bc)
    echo -e "${BLUE}║${NC} Benchmark vs Terminal: ${YELLOW}${SPEEDUP}x faster${NC}                                ${BLUE}║${NC}"
fi

echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BLUE}║${NC} All results saved in: ${OUTPUT_DIR}/                           ${BLUE}║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}Benchmark suite complete!${NC}"
echo -e "Review detailed logs in ${OUTPUT_DIR}/ directory\n"

# Generate comparison chart
echo -e "${BLUE}Performance Comparison:${NC}"
echo "=================================="

# Simple ASCII bar chart
max_rate=$(printf "%s\n%s\n%s" "$TERMINAL_RATE" "$FILE_RATE" "$BENCHMARK_RATE" | sort -n | tail -1)

print_bar() {
    local label=$1
    local rate=$2
    local max=$3
    local width=50
    local filled=$(echo "scale=0; $rate * $width / $max" | bc)
    
    printf "%-15s |" "$label"
    for ((i=0; i<filled; i++)); do printf "█"; done
    printf " %s ev/s\n" "$rate"
}

print_bar "Terminal" "$TERMINAL_RATE" "$max_rate"
print_bar "File" "$FILE_RATE" "$max_rate"
print_bar "Benchmark" "$BENCHMARK_RATE" "$max_rate"

echo ""