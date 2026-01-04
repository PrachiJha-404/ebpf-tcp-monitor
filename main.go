package main

import (
	"bufio" //Buffered I/O for reading files
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal" //Handle OS signals like Ctrl+C
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic" //Atomic operations for thread safe counters
	"syscall"
	"time"
	"unsafe" //Unsafe pointer operations

	"github.com/cilium/ebpf/link" //eBPF program attachment
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit" //Resource limit manipulation
)

//Benchmark infrastructure

type BenchmarkMetrics struct {
	StartTime       time.Time
	EventsRead      atomic.Uint64
	EventsDropped   atomic.Uint64
	RingbufErrors   atomic.Uint64
	BytesProcessed  atomic.Uint64
	ContextSwitches atomic.Uint64

	// Latency Tracking
	LatenciesMicros []uint64
	//Each entry is the time (in microseconds) it took for an event to travel from the Kernel to our Go app.
	latencyIndex atomic.Uint32
	// Circular pointer
}

func NewBenchmarkMetrics() *BenchmarkMetrics {
	return &BenchmarkMetrics{
		StartTime:       time.Now(),
		LatenciesMicros: make([]uint64, 10000),
	}
}

func (b *BenchmarkMetrics) RecordEvent(byteSize int) {
	b.EventsRead.Add(1)
	b.BytesProcessed.Add(uint64(byteSize))
	// 'byteSize' is len(record.RawSample)
}

func (b *BenchmarkMetrics) RecordLatency(micros uint64) {
	idx := b.latencyIndex.Add(1) % 10000
	if int(idx) < len(b.LatenciesMicros) {
		b.LatenciesMicros[idx] = micros
	}
}

func (b *BenchmarkMetrics) GetPercentile(p float64) uint64 {
	samples := make([]uint64, len(b.LatenciesMicros))
	//Copy to avoid race
	copy(samples, b.LatenciesMicros)

	valid := samples[:0]
	for _, v := range samples {
		if v > 0 {
			valid = append(valid, v)
		}
	}
	if len(valid) == 0 {
		return 0
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i] < valid[j] })
	idx := int(float64(len(valid)) * p)
	if idx >= len(valid) {
		idx = len(valid) - 1
	}
	return valid[idx]
}

func (b *BenchmarkMetrics) Report() {
	elapsed := time.Since(b.StartTime).Seconds()
	eventsRead := b.EventsRead.Load()
	eventsDropped := b.EventsDropped.Load()
	errors := b.RingbufErrors.Load()
	bytes := b.BytesProcessed.Load()

	throughput := float64(eventsRead) / elapsed
	mbps := float64(bytes) / elapsed / 1024 / 1024 //Mega Bytes per sec
	dropRate := 0.0
	if eventsRead+eventsDropped > 0 {
		dropRate = float64(eventsDropped) / float64(eventsRead+eventsDropped) * 100
	}

	p50 := b.GetPercentile(0.50)
	p95 := b.GetPercentile(0.95)
	p99 := b.GetPercentile(0.99)

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Println("\n╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      BENCHMARK REPORT                                ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Duration:              %-10.2f seconds                            ║\n", elapsed)
	fmt.Printf("║ Events Processed:      %-10d events                             ║\n", eventsRead)
	fmt.Printf("║ Events Dropped:        %-10d (%.2f%%)                            ║\n", eventsDropped, dropRate)
	fmt.Printf("║ Ring Buffer Errors:    %-10d                                     ║\n", errors)
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Throughput:            %-10.0f events/sec                        ║\n", throughput)
	fmt.Printf("║ Bandwidth:             %-10.2f MB/sec                            ║\n", mbps)
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Latency P50:           %-10d µs                                  ║\n", p50)
	fmt.Printf("║ Latency P95:           %-10d µs                                  ║\n", p95)
	fmt.Printf("║ Latency P99:           %-10d µs                                  ║\n", p99)
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Memory Allocated:      %-10.2f MB                               ║\n", float64(m.Alloc)/1024/1024)
	fmt.Printf("║ Total Allocated:       %-10.2f MB                               ║\n", float64(m.TotalAlloc)/1024/1024)
	fmt.Printf("║ Num GC Runs:           %-10d                                     ║\n", m.NumGC)
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")

}

func (b *BenchmarkMetrics) StreamingReport() {
	lastEvents := uint64(0)
	lastTime := time.Now()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	//Loop runs every second
	for range ticker.C {
		now := time.Now()
		current := b.EventsRead.Load()
		dropped := b.EventsDropped.Load()

		elapsed := now.Sub(lastTime).Seconds()
		eps := float64(current-lastEvents) / elapsed

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		fmt.Printf("[%s] EPS: %8.0f | Total: %10d | Dropped: %6d | Mem: %6.1fMB | GC: %d\n",
			now.Format("15:04:05"),
			eps,
			current,
			dropped,
			float64(m.Alloc)/1024/1024,
			m.NumGC)

		lastEvents = current
		lastTime = now
	}
}

// Global Cache
// var symbolCache = map[uint64]string{}
// Fix: Function name
// Symbol Table Structure
type Symbol struct {
	Addr uint64
	Name string
}

var symbolList []Symbol // A sorted slice instead of a map

func loadSymbols() {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		log.Printf("Warning: could not open kallsyms: %v", err)
		return
	}
	defer file.Close()
	// Format: ADDRESS TYPE NAME
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue //Skip malformed lines
		}
		// Address is field 0, Name is field 2
		addr, _ := strconv.ParseUint(fields[0], 16, 64)
		// symbolCache[addr] = fields[2]
		symbolList = append(symbolList, Symbol{Addr: addr, Name: fields[2]})
	}

	// Sort by address so we can use binary search
	sort.Slice(symbolList, func(i, j int) bool {
		return symbolList[i].Addr < symbolList[j].Addr
	})
}

func findNearestSymbol(addr uint64) string {
	// Find the first element greater than addr
	idx := sort.Search(len(symbolList), func(i int) bool {
		return symbolList[i].Addr > addr
	})

	// The nearest symbol is the one right before that
	if idx > 0 {
		match := symbolList[idx-1]
		offset := addr - match.Addr
		// Only return if it's reasonably close (e.g., within 0x10000 bytes)
		// This prevents matching totally unrelated symbols
		if offset < 0x10000 {
			return fmt.Sprintf("%s+0x%x", match.Name, offset)
		}
	}
	return fmt.Sprintf("0x%x", addr)
}

type Config struct {
	// Output control
	EnablePrinting bool
	PrintInterval  time.Duration

	// Benchmark mode
	BenchmarkMode     bool
	BenchmarkDuration time.Duration

	// Sampling
	SampleRate uint32 // Print 1 in N events
}

func DefaultConfig() *Config {
	return &Config{
		EnablePrinting:    true,
		PrintInterval:     0, // 0 = print everything
		BenchmarkMode:     false,
		BenchmarkDuration: 30 * time.Second,
		SampleRate:        1, // No sampling
	}
}

func main() {

	loadSymbols()

	config := DefaultConfig()
	if len(os.Args) > 1 {
		if os.Args[1] == "benchmark" {
			config.BenchmarkMode = true
			config.EnablePrinting = false
			fmt.Println("Benchmark Mode:")
			fmt.Println("Printing disabled for maximum throughput")
		}
		if len(os.Args) > 2 {
			duration, err := strconv.Atoi(os.Args[2])
			if err == nil {
				config.BenchmarkDuration = time.Duration(duration) * time.Second
			}
		}
	} else if os.Args[1] == "sample" {
		if len(os.Args) > 2 {
			rate, err := strconv.Atoi(os.Args[2])
			if err == nil {
				config.SampleRate = uint32(rate)
				fmt.Printf("SAMPLING MODE: Printing 1 in %d events\n", rate)
			}
		}
	}
	metrics := NewBenchmarkMetrics()

	// Counters for throughput calculation
	// var count uint64     //Total events processed
	// var lastCount uint64 //Events at last metric print

	var dropReasons = map[uint32]string{
		2:  "NOT_SPECIFIED",
		3:  "NO_SOCKET",
		5:  "TCP_CSUM",
		8:  "NETFILTER_DROP",
		21: "TCP_LISTEN_OVERFLOW",
		64: "TCP_RETRANSMIT",
	}
	//1. Allow the program to lock memory for eBPF resources
	//RemoveMemlock() removes restrictions on how much memory current process can lock into RAM
	//Why eBPF programs need this?
	//Linux kernel cannot afford the "slowdown" of waiting for an SSD
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	//2. Load compiled objects into the kernel, create ring buffer map
	objs := monitorObjects{}
	if err := loadMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
	//objs isn't a normal Go struct, it holds File Descriptors of the kernel
	//Prevent Resource Leak.

	//3. Attach to the tcp_drop hook (tracepoint)
	//A link represents the conenction between a program and a hook
	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceTcpDrop, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %v", err)
	}
	defer tp.Close()
	//Puts the NOP back in for the tracepoint

	//4. Open the ring buffer to read data from kernel
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()
	fmt.Println("Monitor Active: Watching for TCP packet drops...")

	//Signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//5. Handle graceful shutdown
	//log.Fatal() would stop the program without closing anything
	stopper := make(chan os.Signal, 1)
	//We create a channel to listen for signals with buffer 1
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	//On recieving Exit, OS pokes the channel instead of immediately killing the program
	//os.Interrupt = SIGINT -= Ctrl+C
	//syscall.SIGTERM - by system tools like Docker, kill <pid> on another terminal

	if config.BenchmarkMode {
		go func() {
			time.Sleep(config.BenchmarkDuration)
			stopper <- syscall.SIGTERM
		}()
	}

	//Event processing goroutine
	go func() {
		var eventNum uint64
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			readStart := time.Now()
			record, err := rd.Read()
			readDuration := time.Since(readStart)

			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				metrics.RingbufErrors.Add(1)
				// atomic.AddUint64(&count, 1) // High-performance thread-safe counter
				// log.Printf("error reading from ringbuf: %v", err)
				continue
			}
			// var event monitorEvent //struct we defined in C!
			// if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, event); err != nil {
			// 	log.Printf("parsing event: %v", err)
			// 	continue
			// }
			if len(record.RawSample) < int(unsafe.Sizeof(monitorEvent{})) {
				metrics.EventsDropped.Add(1)
				// log.Printf("sample too small: %d", len(record.RawSample))
				continue
			}
			//Safety check
			//RawSample is raw, unparsed data that eBPF sent from the kernel
			//RHS is our struct that we are fitting it into
			//If data recieved is too smol we skip

			event := *(*monitorEvent)(unsafe.Pointer(&record.RawSample[0]))
			eventNum++

			metrics.RecordEvent(len(record.RawSample))
			metrics.RecordLatency(uint64(readDuration.Microseconds()))

			// Conditional printing
			if config.EnablePrinting && (eventNum%uint64(config.SampleRate) == 0) {
				reasonStr := dropReasons[event.Reason]
				if reasonStr == "" {
					reasonStr = fmt.Sprintf("UNKNOWN(%d)", event.Reason)
				}

				symbolName := findNearestSymbol(event.Location)
				if symbolName == "" {
					symbolName = fmt.Sprintf("0x%x", event.Location)
				}

				fmt.Printf("[%s] Drop | PID: %-6d | Reason: %-18s| Function: %s\n",
					time.Now().Format("15:04:05"),
					event.Pid,
					reasonStr,
					symbolName)
			}
		}
	}()

	//Metrics goroutine
	go func() {
		if config.BenchmarkMode {
			metrics.StreamingReport()
		} else {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				eventsRead := metrics.EventsRead.Load()
				fmt.Printf("\n--- Total Events: %d ---\n\n", eventsRead)
			}
		}
	}()

	<-stopper
	cancel() //Stop all goroutines
	fmt.Println("\nShutting down...")
	time.Sleep(100 * time.Millisecond) //Give goroutines time to finish
	metrics.Report()
}
