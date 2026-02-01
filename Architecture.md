# Architecture

How the monitor works, from kernel to terminal. This document follows the exact path a single drop event takes through the system.

---

## The Big Picture

```
┌─────────────────────────────────────────────────────────────────┐
│  KERNEL SPACE                                                   │
│                                                                 │
│  packet drop ──► kfree_skb ──► eBPF program ──► ring buffer    │
│                  tracepoint    (monitor.c)       (64KB)         │
│                                                                 │
└───────────────────────────────────┬─────────────────────────────┘
                                    │
                                    │  read()
                                    │
┌───────────────────────────────────▼─────────────────────────────┐
│  USER SPACE                                                     │
│                                                                 │
│  ring buffer ──► unsafe cast ──► symbol lookup ──► format ──► output
│  reader          (monitorEvent)   (/proc/kallsyms)  (256KB buf) │
│  (main.go)                                                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

Three distinct stages. Each one has a specific job and a specific constraint. This doc walks through all of them.

---

## Stage 1: Kernel Side (`monitor.c`)

### The Tracepoint Hook

The kernel has built-in hooks called tracepoints — stable, documented attachment points that don't require modifying kernel source. The one we care about is `skb/kfree_skb`. It fires whenever the kernel frees a socket buffer (skb), which is what happens when a packet is dropped.

```c
SEC("tracepoint/skb/kfree_skb")
int trace_tcp_drop(struct trace_event_raw_kfree_skb *ctx) {
```

The `SEC()` macro tells the eBPF loader which tracepoint to attach to. When the kernel drops any packet anywhere on the system, this function runs.

### Filtering

Not every `kfree_skb` is a meaningful drop. Reason codes 0 and 1 are normal packet lifecycle events (freed after successful delivery). We bail out immediately for those:

```c
    if (ctx->reason <= 1) return 0;
```

This filter runs inside the kernel before anything else. Packets that aren't real drops never touch the ring buffer, never wake up userspace.

### The Event Struct

What we capture per drop:

```c
struct event {
    u32 pid;       // Process context when drop occurred
    u32 reason;    // Kernel's drop reason code
    u64 location;  // Instruction pointer — where in kernel code the drop happened
};
```

16 bytes per event. Deliberately small — we're in kernel space, every byte matters.

### Ring Buffer Write

```c
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;   // Ring buffer full — drop this event silently
    e->pid      = bpf_get_current_pid_tgid() >> 32;
    e->reason   = ctx->reason;
    e->location = (u64)ctx->location;
    bpf_ringbuf_submit(e, 0);
```

`bpf_ringbuf_reserve` claims 16 bytes in the ring buffer. If the buffer is full (userspace isn't reading fast enough), it returns NULL and we silently drop the event — no blocking, no spinning. This is important: the eBPF program must never block or loop waiting. The verifier enforces this.

`bpf_ringbuf_submit` makes the event visible to userspace. Between reserve and submit, the event is allocated but not yet readable — this gives us an atomic write from userspace's perspective.

### Ring Buffer Configuration

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);   // 64KB
    __type(value, struct event);
} events SEC(".maps");
```

64KB circular buffer. `max_entries` must be a power of 2 (kernel requirement). At 16 bytes per event, this holds ~4000 events before it wraps. If userspace can't keep up, older events get silently dropped.

Why ring buffer over other eBPF map types? Perf buffers are per-CPU and require more complex userspace handling. Hash/array maps are for lookups, not event streaming. Ring buffer is purpose-built for this: single buffer, shared across all CPUs, lock-free.

### eBPF Safety

The kernel's eBPF verifier statically analyzes this program before loading it. It proves:
- No infinite loops (our function runs once per event and returns)
- No out-of-bounds memory access
- All paths return a value
- We only call approved helper functions (`bpf_ringbuf_reserve`, `bpf_get_current_pid_tgid`, etc.)

If verification fails, the program doesn't load. This is why eBPF programs can't crash the kernel — the verifier won't let unsafe code in.

---

## Stage 2: Kernel-to-Userspace Bridge

### Why `rlimit.RemoveMemlock()`?

```go
if err := rlimit.RemoveMemlock(); err != nil {
    log.Fatal(err)
}
```

eBPF maps and ring buffers need memory-locked pages — pages that stay in RAM and never get swapped to disk. The kernel can't afford page faults in the hot path where our eBPF program runs.

Non-root users have a default limit on how much memory they can lock (usually 64KB). Our ring buffer alone is 64KB, plus the eBPF program and metadata on top of that. `RemoveMemlock()` raises this limit. It only works because we're already running as root (which we need anyway to load eBPF programs).

### Loading the eBPF Program

```go
objs := monitorObjects{}
if err := loadMonitorObjects(&objs, nil); err != nil {
    log.Fatalf("Loading eBPF objects: %v", err)
}
```

`monitor_bpfel.go` is generated by `bpf2go`. It embeds the compiled eBPF bytecode (`monitor_bpfel.o`) directly into the Go binary via `//go:embed`. `loadMonitorObjects` sends that bytecode to the kernel, which runs it through the verifier and JIT-compiles it.

After this call, `objs.TraceTcpDrop` is a handle to the loaded eBPF program and `objs.Events` is a file descriptor to the ring buffer.

### Attaching to the Tracepoint

```go
tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceTcpDrop, nil)
```

This tells the kernel: "every time `skb/kfree_skb` fires, also run `TraceTcpDrop`." The tracepoint is now live. Packet drops start flowing into the ring buffer.

### Reading the Ring Buffer

```go
rd, err := ringbuf.NewReader(objs.Events)
// ...
record, err := rd.Read()   // blocks until an event is available
```

`rd.Read()` blocks the goroutine until data is available in the ring buffer. When the kernel submits an event via `bpf_ringbuf_submit`, the reader wakes up. This is efficient — no polling, no busy-waiting. The goroutine sleeps until there's actual work.

---

## Stage 3: Userspace Processing (`main.go`)

### Parsing the Event

```go
event := *(*monitorEvent)(unsafe.Pointer(&record.RawSample[0]))
```

The ring buffer gives us raw bytes. We know the layout matches our C struct (same fields, same order, same sizes — enforced by the `structs.HostLayout` tag in the generated Go struct). `unsafe.Pointer` reinterprets those bytes as a `monitorEvent` with zero copying and zero allocation.

This is the only `unsafe` usage in the codebase. It's justified: we control both sides of the data layout, and the alternative (manual byte parsing) would be slower and more error-prone.

### Symbol Resolution

The `location` field is a raw kernel instruction pointer — something like `0xffffffff81a2b574`. Meaningless to a human. We want to know which function that address belongs to.

**Loading symbols:**

```go
func loadSymbols() {
    file, _ := os.Open("/proc/kallsyms")
    // parse each line: address, type, name
    // sort by address
}
```

`/proc/kallsyms` contains every symbol in the running kernel — around 200,000 entries. We load and sort them once at startup.

**Looking up a symbol:**

```go
func findNearestSymbol(addr uint64) string {
    idx := sort.Search(len(symbolList), func(i int) bool {
        return symbolList[i].Addr > addr
    })
    // symbolList[idx-1] is the function that contains our address
    // offset = addr - symbolList[idx-1].Addr
}
```

Binary search finds the last symbol whose address is ≤ our target. That's the function our address falls inside. The offset tells us how far into the function the drop happened.

Example: address `0xffffffff81a2b574` falls between `tcp_v4_syn_recv_sock` (at `0x...b340`) and the next function (at `0x...b580`). Result: `tcp_v4_syn_recv_sock+0x234`.

**Why this is expensive:** Binary search through 200K entries is O(log n) — fast algorithmically, but it's 17-18 comparisons per event, each touching a different cache line. At hundreds of thousands of events per second, this adds up. It's a known bottleneck and a candidate for optimization (per-reason caching, since most drops come from the same few functions).

### Event Processing Modes

Four modes exist to isolate different parts of the pipeline for benchmarking:

```
benchmark:  read event → count it → done
            (measures: raw ring buffer throughput)

busy:       read event → symbol lookup → format string → discard
            (measures: processing cost without I/O)

file:       read event → symbol lookup → format string → buffered write to file
            (measures: full pipeline with I/O)

terminal:   read event → symbol lookup → format string → write to TTY
            (measures: full pipeline, TTY-limited)
```

The difference between `benchmark` and `busy` isolates processing cost. The difference between `busy` and `file` isolates I/O cost. The difference between `file` and `terminal` isolates TTY overhead.

This breakdown was built to answer a specific question: "Is printing the bottleneck?" The answer turned out to be more complicated than expected — see the Open Questions section in the README.

### Output Buffering

```go
buffered: bufio.NewWriterSize(output, 256*1024)  // 256KB buffer
```

Writing one line at a time to a file or terminal is expensive — each write is a syscall. A 256KB buffer batches many events into a single write. `Flush()` is called on shutdown to make sure nothing is lost.

### Metrics

All counters use `sync/atomic`:

```go
EventsRead    atomic.Uint64
EventsPrinted atomic.Uint64
BytesWritten  atomic.Uint64
```

The metrics reporter goroutine reads these every second. Atomic operations let it read safely while the event processing goroutine writes, without locks or mutexes. The final report also pulls `runtime.MemStats` for GC run count and heap allocation — useful for understanding memory pressure at high event rates.

### Shutdown

```go
stopper := make(chan os.Signal, 1)
signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

go func() {
    time.Sleep(time.Duration(duration) * time.Second)
    stopper <- syscall.SIGTERM
}()
```

Two shutdown triggers: Ctrl+C from the user, or the auto-stop timer. Both send to the same channel. The event reader goroutine checks this channel on each iteration. After stop, we flush the output buffer and give the reader 500ms to finish any in-flight events before printing the final report.

---

## Data Flow Summary

```
Kernel drops packet
        │
        ▼
kfree_skb tracepoint fires
        │
        ▼
eBPF program runs (monitor.c)
  ├── reason ≤ 1? → return (not a real drop)
  └── reserve 16 bytes in ring buffer
      ├── buffer full? → return (event lost)
      └── write pid, reason, location
          └── submit (event now visible to userspace)
                │
                ▼
        Go reader wakes up (main.go)
                │
                ▼
        unsafe cast raw bytes → monitorEvent
                │
                ▼
        binary search /proc/kallsyms → function name
                │
                ▼
        format string with reason + symbol
                │
                ▼
        write to 256KB buffer
                │
                ▼ (on flush or buffer full)
        output (terminal / file)
```

---

## Known Limitations

**PID accuracy:** `bpf_get_current_pid_tgid()` returns whichever process the kernel happens to be running when the drop occurs. For `TCP_LISTEN_OVERFLOW` this is typically the listening process. For drops that happen in kernel threads or during interrupt handling, it may be unrelated to the actual connection owner.

**Ring buffer overflow:** If userspace can't read fast enough, events are silently dropped. The `bpf_ringbuf_reserve` returns NULL and the eBPF program skips that event. There's no backpressure — the kernel side never blocks.

**`kfree_skb` is system-wide:** We hook every packet drop on the entire machine, not just TCP. The reason filter (`> 1`) removes normal frees, but at extreme drop rates the hook itself adds overhead to the kernel path.

**Symbol accuracy:** `/proc/kallsyms` shows addresses as zero for non-root users. We require root anyway (for eBPF), so this isn't a practical issue — but it means this tool can't work without elevated privileges even if the eBPF capability requirements change in the future.