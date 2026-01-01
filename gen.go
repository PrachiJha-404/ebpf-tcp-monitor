package main

//go:generate /usr/local/go/bin/go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -go-package main monitor bpf/monitor.c -- -I./bpf
