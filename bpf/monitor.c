// +build ignore
//Above comment is a Go directive
//Tells Go to ignore this file when we run go build
//Otherwise it tries to compile it using cgo 
//And we are only using this fiel for eBPF generation

#include "vmlinux.h" //Single file that contains every struct def in current kernel
#include <bpf/bpf_helpers.h> 

struct event{
    u32 pid;
    u32 reason;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); //FIFO Queue, better than PerfBuffer cuz its shared across all CPUs
    __uint(max_entries, 1 << 16); //Buffer size must be a power of 2
} events SEC(".maps"); //ELF section marker
//Tells the kernel this is a data structure def and not to execute it
//Allocate memory for this buffer when you load the program

SEC("tracepoint/skb/kfree_skb") //hook
int trace_tcp_drop(struct trace_event_raw_kfree_skb *ctx){
    if (ctx->reason <= 1) return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->reason = ctx->reason;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";

