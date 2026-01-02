package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Global Cache
// var symbolCache = map[uint64]string{}
// Fix: Function name
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

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
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

func main() {

	loadSymbols()

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
	//2. Load compiled objects (ring buf stuff) into the kernel
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

	//5. Handle graceful shutdown
	//log.Fatal() would stop the program without closing anything
	stopper := make(chan os.Signal, 1)
	//We create a channel to listen for signals with buffer 1
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	//On recieving Exit, OS pokes the channel instead of immediately killing the program
	//os.Interrupt = SIGINT -= Ctrl+C
	//syscall.SIGTERM - by system tools like Docker, kill <pid> on another terminal

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("error reading from ringbuf: %v", err)
				continue
			}
			var event monitorEvent //struct we defined in C!
			// if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, event); err != nil {
			// 	log.Printf("parsing event: %v", err)
			// 	continue
			// }
			if len(record.RawSample) < int(unsafe.Sizeof(monitorEvent{})) {
				log.Printf("sample too small: %d", len(record.RawSample))
				continue
			}
			//Safety check
			//RawSample is raw, unparsed data that eBPF sent from the kernel
			//RHS is our struct that we are fitting it into
			//If data recieved is too smol we skip

			event = *(*monitorEvent)(unsafe.Pointer(&record.RawSample[0]))
			reasonStr := dropReasons[event.Reason]
			if reasonStr == "" {
				reasonStr = fmt.Sprintf("UNKNOWN(%d)", event.Reason)
			}

			// symbolName := symbolCache[event.Location]
			symbolName := findNearestSymbol(event.Location)
			if symbolName == "" {
				// Fallback to hex if not found
				symbolName = fmt.Sprintf("0x%x", event.Location)
			}
			fmt.Printf("[%s] Drop Detected | PID: %-6d | Reason: %-18s| Function: %s\n", time.Now().Format("15:04:05"), event.Pid, reasonStr, symbolName)
		}
	}()

	<-stopper
	//Blocking read form a channel (code doesn't move forward until this recieves smth)
	fmt.Println("\nShutting down...")

}
