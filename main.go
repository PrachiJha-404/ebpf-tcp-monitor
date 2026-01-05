package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ============================================================================
// METRICS TRACKING
// ============================================================================

type Metrics struct {
	StartTime     time.Time
	EventsRead    atomic.Uint64
	EventsPrinted atomic.Uint64
	BytesWritten  atomic.Uint64
}

func NewMetrics() *Metrics {
	return &Metrics{StartTime: time.Now()}
}

func (m *Metrics) Report() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastCount := uint64(0)
	lastTime := time.Now()

	for range ticker.C {
		now := time.Now()
		current := m.EventsRead.Load()

		elapsed := now.Sub(lastTime).Seconds()
		eps := float64(current-lastCount) / elapsed

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		// Always print to stderr so it doesn't interfere with stdout redirection
		fmt.Fprintf(os.Stderr, "[%s] Rate: %8.0f ev/s | Total: %10d | Mem: %5.1f MB\n",
			now.Format("15:04:05"),
			eps,
			current,
			float64(mem.Alloc)/1024/1024)

		lastCount = current
		lastTime = now
	}
}

func (m *Metrics) FinalReport(modeName string) {
	elapsed := time.Since(m.StartTime).Seconds()
	read := m.EventsRead.Load()
	printed := m.EventsPrinted.Load()
	bytesWritten := m.BytesWritten.Load()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	fmt.Fprintln(os.Stderr, "\n╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Fprintf(os.Stderr, "║  %-66s  ║\n", modeName)
	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintf(os.Stderr, "║ Duration:           %8.2f seconds                                   ║\n", elapsed)
	fmt.Fprintf(os.Stderr, "║ Events Read:        %8d                                           ║\n", read)

	if printed > 0 {
		fmt.Fprintf(os.Stderr, "║ Events Printed:     %8d                                           ║\n", printed)
		fmt.Fprintf(os.Stderr, "║ Bytes Written:      %8.2f MB                                      ║\n", float64(bytesWritten)/1024/1024)
	}

	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintf(os.Stderr, "║ Throughput:         %8.0f events/sec                               ║\n", float64(read)/elapsed)

	if printed > 0 {
		fmt.Fprintf(os.Stderr, "║ Print Rate:         %8.0f events/sec                               ║\n", float64(printed)/elapsed)
		fmt.Fprintf(os.Stderr, "║ Write Bandwidth:    %8.2f MB/sec                                  ║\n", float64(bytesWritten)/elapsed/1024/1024)
	}

	fmt.Fprintln(os.Stderr, "╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintf(os.Stderr, "║ Memory Allocated:   %8.2f MB                                       ║\n", float64(mem.Alloc)/1024/1024)
	fmt.Fprintf(os.Stderr, "║ Total Allocated:    %8.2f MB                                       ║\n", float64(mem.TotalAlloc)/1024/1024)
	fmt.Fprintf(os.Stderr, "║ GC Runs:            %8d                                            ║\n", mem.NumGC)
	fmt.Fprintln(os.Stderr, "╚══════════════════════════════════════════════════════════════════════╝")
}

// ============================================================================
// SYMBOL RESOLUTION
// ============================================================================

type Symbol struct {
	Addr uint64
	Name string
}

var symbolList []Symbol

func loadSymbols() {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Printf("Warning: could not open kallsyms: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		addr, _ := strconv.ParseUint(fields[0], 16, 64)
		symbolList = append(symbolList, Symbol{Addr: addr, Name: fields[2]})
	}

	sort.Slice(symbolList, func(i, j int) bool {
		return symbolList[i].Addr < symbolList[j].Addr
	})

	fmt.Fprintf(os.Stderr, "✓ Loaded %d kernel symbols\n", len(symbolList))
}

func findNearestSymbol(addr uint64) string {
	idx := sort.Search(len(symbolList), func(i int) bool {
		return symbolList[i].Addr > addr
	})

	if idx > 0 {
		match := symbolList[idx-1]
		offset := addr - match.Addr
		if offset < 0x10000 {
			return fmt.Sprintf("%s+0x%x", match.Name, offset)
		}
	}
	return fmt.Sprintf("0x%x", addr)
}

// ============================================================================
// EVENT PROCESSING
// ============================================================================

type EventProcessor struct {
	writer      io.Writer
	buffered    *bufio.Writer
	metrics     *Metrics
	dropReasons map[uint32]string
}

func NewEventProcessor(output io.Writer, metrics *Metrics) *EventProcessor {
	return &EventProcessor{
		writer:   output,
		buffered: bufio.NewWriterSize(output, 256*1024), // 256KB buffer
		metrics:  metrics,
		dropReasons: map[uint32]string{
			2:  "NOT_SPECIFIED",
			3:  "NO_SOCKET",
			5:  "TCP_CSUM",
			8:  "NETFILTER_DROP",
			21: "TCP_LISTEN_OVERFLOW",
			64: "TCP_RETRANSMIT",
		},
	}
}

func (p *EventProcessor) ProcessEvent(event *monitorEvent, doPrint bool) {
	p.metrics.EventsRead.Add(1)

	if !doPrint {
		return
	}

	// Format the event
	reasonStr := p.dropReasons[event.Reason]
	if reasonStr == "" {
		reasonStr = fmt.Sprintf("UNKNOWN(%d)", event.Reason)
	}

	symbolName := findNearestSymbol(event.Location)
	if symbolName == "" {
		symbolName = fmt.Sprintf("0x%x", event.Location)
	}

	// Write to buffer
	n, _ := fmt.Fprintf(p.buffered, "[%s] Drop | PID: %-6d | Reason: %-18s | Function: %s\n",
		time.Now().Format("15:04:05"),
		event.Pid,
		reasonStr,
		symbolName)

	p.metrics.EventsPrinted.Add(1)
	p.metrics.BytesWritten.Add(uint64(n))
}

// ProcessEventBusy does all the work of file mode but discards output
func (p *EventProcessor) ProcessEventBusy(event *monitorEvent) {
	p.metrics.EventsRead.Add(1)

	// Do ALL the same expensive work as file mode
	reasonStr := p.dropReasons[event.Reason]
	if reasonStr == "" {
		reasonStr = fmt.Sprintf("UNKNOWN(%d)", event.Reason)
	}

	// This is the expensive part (binary search through kernel symbols)
	symbolName := findNearestSymbol(event.Location)
	if symbolName == "" {
		symbolName = fmt.Sprintf("0x%x", event.Location)
	}

	// Format the string (allocates memory, same as file mode)
	_ = fmt.Sprintf("[%s] Drop | PID: %-6d | Reason: %-18s | Function: %s\n",
		time.Now().Format("15:04:05"),
		event.Pid,
		reasonStr,
		symbolName)

	// But DON'T write it (testing if the work itself helps)
	p.metrics.EventsPrinted.Add(1)
}

func (p *EventProcessor) Flush() {
	p.buffered.Flush()
}

// ============================================================================
// BENCHMARK MODES
// ============================================================================

type BenchmarkMode struct {
	Name        string
	DoPrint     bool
	Output      io.Writer
	Description string
}

func getModes() map[string]BenchmarkMode {
	return map[string]BenchmarkMode{
		"terminal": {
			Name:        "TERMINAL MODE",
			DoPrint:     true,
			Output:      os.Stdout,
			Description: "Print each event to terminal (slowest, limited by TTY)",
		},
		"file": {
			Name:        "FILE MODE",
			DoPrint:     true,
			Output:      nil, // Set dynamically
			Description: "Print to file via stdout redirect (tests buffered I/O)",
		},
		"benchmark": {
			Name:        "BENCHMARK MODE",
			DoPrint:     false,
			Output:      io.Discard,
			Description: "No printing, pure counting (tests max throughput)",
		},
		"busy": {
			Name:        "BUSY MODE",
			DoPrint:     false,
			Output:      io.Discard,
			Description: "Do all work except print (tests if work helps throughput)",
		},
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <mode> <duration_seconds>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Modes:\n")

		modes := getModes()
		for key, mode := range modes {
			fmt.Fprintf(os.Stderr, "  %-10s - %s\n", key, mode.Description)
		}

		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s terminal 30              # Print to terminal\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s file 30 > output.txt     # Redirect to file\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s benchmark 30             # Pure counting\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nComparison script:\n")
		fmt.Fprintf(os.Stderr, "  ./compare.sh               # Runs all 3 benchmarks\n")
		os.Exit(1)
	}

	modeKey := os.Args[1]
	duration, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid duration: %v", err)
	}

	modes := getModes()
	mode, ok := modes[modeKey]
	if !ok {
		log.Fatalf("Invalid mode '%s'. Use: terminal, file, or benchmark", modeKey)
	}

	// Special handling for file mode
	if modeKey == "file" {
		// Check if stdout is redirected
		stat, _ := os.Stdout.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			log.Fatalf("FILE mode requires stdout redirection. Use: %s file 30 > output.txt", os.Args[0])
		}
		mode.Output = os.Stdout
	}

	// Setup
	fmt.Fprintf(os.Stderr, "╔══════════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(os.Stderr, "║  %-66s  ║\n", mode.Name)
	fmt.Fprintf(os.Stderr, "╠══════════════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(os.Stderr, "║ %s%-66s%s ║\n", "", mode.Description, "")
	fmt.Fprintf(os.Stderr, "║ Duration: %-57d seconds ║\n", duration)
	fmt.Fprintf(os.Stderr, "╚══════════════════════════════════════════════════════════════════════╝\n\n")

	loadSymbols()
	metrics := NewMetrics()

	// eBPF setup
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := monitorObjects{}
	if err := loadMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceTcpDrop, nil)
	if err != nil {
		log.Fatalf("Attaching tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf: %v", err)
	}
	defer rd.Close()

	processor := NewEventProcessor(mode.Output, metrics)

	fmt.Fprintf(os.Stderr, "✓ eBPF program loaded and attached\n")
	fmt.Fprintf(os.Stderr, "✓ Starting in 3 seconds...\n\n")
	time.Sleep(3 * time.Second)

	// Signal handling
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Auto-stop timer
	go func() {
		time.Sleep(time.Duration(duration) * time.Second)
		stopper <- syscall.SIGTERM
	}()

	// Metrics reporter (only in benchmark mode to avoid cluttering terminal)
	if modeKey == "benchmark" {
		go metrics.Report()
	}

	// Event reader
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stopper:
				return
			default:
			}

			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			if len(record.RawSample) < int(unsafe.Sizeof(monitorEvent{})) {
				continue
			}

			event := *(*monitorEvent)(unsafe.Pointer(&record.RawSample[0]))

			if modeKey == "busy" {
				processor.ProcessEventBusy(&event)
			} else {
				processor.ProcessEvent(&event, mode.DoPrint)
			}
		}
	}()

	// Wait for stop signal
	<-stopper

	// Flush any remaining buffered output
	processor.Flush()

	// Give reader goroutine time to finish
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}

	metrics.FinalReport(mode.Name)
}
