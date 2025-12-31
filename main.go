package main

import (
	"log"

	//??

	"github.com/cilium/ebpf/rlimit"
)

func main() {
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

}
