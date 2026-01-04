package main

import (
	"bufio"
	"errors"
	"fmt"
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
// METRICS
// ============================================================================

type Metrics struct {
	StartTime     time.Time
	EventsRead    atomic.Uint64
	EventsPrinted atomic.Uint64
	EventsDropped atomic.Uint64
}

func NewMetrics() *Metrics {
	return &Metrics{StartTime: time.Now()}
}

func (m *Metrics) StreamingReport(printMode bool) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	lastCount := uint64(0)
	lastTime := time.Now()

	for range ticker.C {
		now := time.Now()
		current := m.EventsRead.Load()
		dropped := m.EventsDropped.Load()

		elapsed := now.Sub(lastTime).Seconds()
		eps := float64(current-lastCount) / elapsed

		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

		// Print to stderr so it doesn't interfere with output redirection
		fmt.Fprintf(os.Stderr, "[%s] EPS: %8.0f | Total: %10d | Dropped: %6d | Mem: %6.1fMB\n",
			now.Format("15:04:05"),
			eps,
			current,
			dropped,
			float64(mem.Alloc)/1024/1024)

		lastCount = current
		lastTime = now
	}
}

func (m *Metrics) FinalReport(printMode bool) {
	elapsed := time.Since(m.StartTime).Seconds()
	read := m.EventsRead.Load()
	printed := m.EventsPrinted.Load()
	dropped := m.EventsDropped.Load()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	// Always print to stderr so results are visible even with stdout redirect
	out := os.Stderr

	fmt.Fprintln(out, "\n╔══════════════════════════════════════════════════════════════════════╗")
	if printMode {
		fmt.Fprintln(out, "║                    PRINT MODE BENCHMARK REPORT                       ║")
	} else {
		fmt.Fprintln(out, "║                  BENCHMARK MODE REPORT (NO PRINTING)                 ║")
	}
	fmt.Fprintln(out, "╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintf(out, "║ Duration:              %-10.2f seconds                            ║\n", elapsed)
	fmt.Fprintf(out, "║ Events Read:           %-10d events                             ║\n", read)

	if printMode {
		fmt.Fprintf(out, "║ Events Printed:        %-10d events                             ║\n", printed)
	}

	fmt.Fprintf(out, "║ Events Dropped:        %-10d (%.2f%%)                            ║\n",
		dropped, float64(dropped)/float64(read+dropped)*100)
	fmt.Fprintln(out, "╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintf(out, "║ Read Throughput:       %-10.0f events/sec                        ║\n", float64(read)/elapsed)

	if printMode {
		fmt.Fprintf(out, "║ Print Throughput:      %-10.0f events/sec                        ║\n", float64(printed)/elapsed)
	}

	fmt.Fprintf(out, "║ Bandwidth:             %-10.2f MB/sec                            ║\n", float64(read*16)/elapsed/1024/1024)
	fmt.Fprintln(out, "╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Fprintf(out, "║ Memory Allocated:      %-10.2f MB                               ║\n", float64(mem.Alloc)/1024/1024)
	fmt.Fprintf(out, "║ Total Allocated:       %-10.2f MB                               ║\n", float64(mem.TotalAlloc)/1024/1024)
	fmt.Fprintf(out, "║ Num GC Runs:           %-10d                                     ║\n", mem.NumGC)
	fmt.Fprintln(out, "╚══════════════════════════════════════════════════════════════════════╝")
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
// MAIN
// ============================================================================

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <mode> <duration_seconds>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nModes:\n")
		fmt.Fprintf(os.Stderr, "  print      - Print every event (measures I/O bottleneck)\n")
		fmt.Fprintf(os.Stderr, "  benchmark  - Count only, no printing (measures max throughput)\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s print 30           # Print mode for 30 seconds\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s benchmark 30       # Benchmark mode for 30 seconds\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s print 30 > out.txt # Redirect prints to file\n", os.Args[0])
		os.Exit(1)
	}

	mode := os.Args[1]
	duration, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid duration: %v", err)
	}

	printMode := false
	switch mode {
	case "print":
		printMode = true
	case "benchmark":
		printMode = false
	default:
		log.Fatalf("Invalid mode: %s (use 'print' or 'benchmark')", mode)
	}

	loadSymbols()
	metrics := NewMetrics()

	dropReasons := map[uint32]string{
		2:  "NOT_SPECIFIED",
		3:  "NO_SOCKET",
		5:  "TCP_CSUM",
		8:  "NETFILTER_DROP",
		21: "TCP_LISTEN_OVERFLOW",
		64: "TCP_RETRANSMIT",
	}

	// eBPF setup
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := monitorObjects{}
	if err := loadMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceTcpDrop, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Print startup message to stderr
	if printMode {
		fmt.Fprintf(os.Stderr, "🖨️  PRINT MODE: Every event will be printed\n")
		fmt.Fprintf(os.Stderr, "   Duration: %d seconds\n", duration)
		fmt.Fprintf(os.Stderr, "   Events will print to stdout\n")
		fmt.Fprintf(os.Stderr, "   Metrics will print to stderr\n")
	} else {
		fmt.Fprintf(os.Stderr, "🔬 BENCHMARK MODE: No printing (maximum throughput)\n")
		fmt.Fprintf(os.Stderr, "   Duration: %d seconds\n", duration)
	}
	fmt.Fprintf(os.Stderr, "\n   Starting in 3 seconds...\n\n")
	time.Sleep(3 * time.Second)

	// Signal handling
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Auto-stop timer
	go func() {
		time.Sleep(time.Duration(duration) * time.Second)
		stopper <- syscall.SIGTERM
	}()

	// Streaming metrics (to stderr, won't interfere with stdout)
	if !printMode {
		go metrics.StreamingReport(printMode)
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
				metrics.EventsDropped.Add(1)
				continue
			}

			event := *(*monitorEvent)(unsafe.Pointer(&record.RawSample[0]))
			metrics.EventsRead.Add(1)

			if printMode {
				// PRINT TO STDOUT (this is what we're measuring!)
				reasonStr := dropReasons[event.Reason]
				if reasonStr == "" {
					reasonStr = fmt.Sprintf("UNKNOWN(%d)", event.Reason)
				}

				symbolName := findNearestSymbol(event.Location)
				if symbolName == "" {
					symbolName = fmt.Sprintf("0x%x", event.Location)
				}

				// Print to STDOUT
				fmt.Printf("[%s] Drop | PID: %-6d | Reason: %-18s | Function: %s\n",
					time.Now().Format("15:04:05"),
					event.Pid,
					reasonStr,
					symbolName)

				metrics.EventsPrinted.Add(1)
			}
			// In benchmark mode, we just count and continue (no printing)
		}
	}()

	// Wait for stop
	<-stopper

	// Give reader goroutine time to finish
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}

	metrics.FinalReport(printMode)
}
