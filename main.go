package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

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

			event = *(*monitorEvent)(unsafe.Pointer(&record.RawSample[0]))
			reasonStr := dropReasons[event.Reason]
			if reasonStr == "" {
				reasonStr = fmt.Sprintf("UNKNOWN(%d)", event.Reason)
			}
			fmt.Printf("[%s] Drop Detected | PID: %-6d | Reason: %s\n", time.Now().Format("15:04:05"), event.Pid, reasonStr)
		}
	}()

	<-stopper
	//Blocking read form a channel (code doesn't move forward until this recieves smth)
	fmt.Println("\nShutting down...")

}
