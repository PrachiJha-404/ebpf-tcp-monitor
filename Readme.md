# ebpf-tcp-monitor

Real-time TCP packet drop monitoring using eBPF. Hooks into the Linux kernel's `kfree_skb` tracepoint to capture per-process TCP drop events — the stuff that never shows up in your application logs.

## Why This Exists

I was load testing a Go auction server with 1000 concurrent clients. Connections kept failing with "connection refused" but my application logs showed nothing useful. Turns out my code was so fast it was overwhelming the kernel's TCP listen queue — the drops were happening below my application, invisible to it.

`netstat -s` told me *something* was dropping packets system-wide. But not which process, not why, not in real time.

This tool gives you that visibility.

## What It Shows

```
[15:04:23] Drop | PID: 1234 | Reason: TCP_LISTEN_OVERFLOW | Function: tcp_v4_syn_recv_sock+0x234
[15:04:23] Drop | PID: 1234 | Reason: TCP_LISTEN_OVERFLOW | Function: tcp_v4_syn_recv_sock+0x234
[15:04:23] Drop | PID: 5678 | Reason: NETFILTER_DROP      | Function: nf_hook_slow+0x12a
```

For each drop event: which process was in context, why the kernel dropped it, and exactly which kernel function did the dropping.

## Requirements

- Linux kernel 5.8+ with BTF support
- Go 1.21+
- Root / sudo (eBPF requires permission to load programs into the kernel)
- `clang` (only needed if recompiling the eBPF C code)

## Installation

```bash
git clone https://github.com/your-username/ebpf-tcp-monitor.git
cd ebpf-tcp-monitor

# If you need to recompile the eBPF program (monitor.c -> monitor_bpfel.o):
# clang -g -O2 -target bpf -I/usr/src/linux-headers-$(uname -r)/include -c monitor.c -o monitor_bpfel.o

# Build the Go binary
go build -o monitor .
```

## Usage

```bash
sudo ./monitor <mode> <duration_seconds>
```

### Modes

| Mode | What it does | When to use |
|---|---|---|
| `terminal` | Prints every drop event to stdout | Watching drops in real time |
| `file` | Prints to stdout (redirect to file) | Capturing drops for analysis |
| `benchmark` | Counts events only, no output | Measuring max throughput |
| `busy` | Does all processing work, no I/O | Isolating processing vs I/O cost |

### Examples

```bash
# Watch drops in real time
sudo ./monitor terminal 30

# Capture drops to a file for analysis
sudo ./monitor file 60 > drops.txt

# Measure how fast the monitor can process events
sudo ./monitor benchmark 30
```

### Running All Modes at Once

`compare.sh` runs all four modes sequentially and saves every log to `benchmark_results/`:

```bash
sudo bash compare.sh        # 30 seconds per mode (default)
sudo bash compare.sh 60     # 60 seconds per mode
```

Results get saved to `benchmark_results/` with timestamps:
```
benchmark_results/
├── terminal_20260131_220000.log      # terminal mode metrics
├── file_20260131_220000.log          # file mode metrics
├── drops_20260131_220000.txt         # actual drop events captured in file mode
├── benchmark_20260131_220000.log     # benchmark mode metrics + live rate
└── busy_20260131_220000.log          # busy mode metrics + live rate
```

> Note: The summary comparison at the end of `compare.sh` is currently commented out (work in progress). Compare the `Throughput` lines in the log files manually for now.

## Generating TCP Drops (for testing)

The monitor only fires when the kernel actually drops packets. If your system is healthy, you won't see much. To generate drops for testing:

```bash
# Reduce the listen queue so it overflows easily
sudo sysctl -w net.core.somaxconn=8

# Start a listener
nc -l 8899 &

# Flood it with SYN packets (triggers TCP_LISTEN_OVERFLOW)
sudo hping3 -S -p 8899 --flood localhost

# In another terminal, run the monitor
sudo ./monitor terminal 30
```

You should see `TCP_LISTEN_OVERFLOW` events appearing immediately.

## Drop Reasons

| Code | Reason | What it means |
|---|---|---|
| 2 | `NOT_SPECIFIED` | Kernel didn't specify why |
| 3 | `NO_SOCKET` | No matching socket for this packet |
| 5 | `TCP_CSUM` | TCP checksum validation failed |
| 8 | `NETFILTER_DROP` | Dropped by a firewall/iptables rule |
| 21 | `TCP_LISTEN_OVERFLOW` | Listen queue full, can't accept connection |
| 64 | `TCP_RETRANSMIT` | Retransmission limit exceeded |

## A Note on PID Accuracy

The PID is captured via `bpf_get_current_pid_tgid()`, which returns the process context active when the drop occurs. For most drop types (especially `TCP_LISTEN_OVERFLOW`), this is the process that owns the connection. For some drops that happen in kernel threads or during interrupt handling, the PID may not correspond to the actual owner of the dropped packet. Use it as a strong signal, not gospel.

## Open Questions

While benchmarking this tool, I ran into something weird: adding buffered file output actually *increased* throughput compared to a no-output baseline. The benchmark mode (pure event counting) was consistently slower than the mode that did symbol resolution, string formatting, AND wrote to a file.

Reproduce it yourself:
```bash
# Generate drops in one terminal
sudo sysctl -w net.core.somaxconn=8
sudo hping3 -S -p 8899 --flood localhost

# Run the benchmark suite in another
sudo bash compare.sh 30
```

Then compare the `Throughput` lines across the four log files in `benchmark_results/`. File and busy modes tend to beat benchmark mode, which shouldn't happen.

Hypotheses so far:
- Ring buffer starvation (tight read loop starves kernel)
- CPU cache effects (I/O pauses improve locality)
- Go scheduler interactions (syscalls trigger beneficial context switches)
- Ring buffer batching (kernel accumulates events during I/O delays)

None confirmed yet. If you have ideas, open an issue or ping me.


## Project Structure

```
|──bpf
|   ├── monitor.c            # eBPF program (kernel side) — hooks kfree_skb
├── monitor_bpfel.go     # Auto-generated Go bindings (bpf2go output)
├── monitor_bpfel.o      # Compiled eBPF bytecode (embedded into binary)
├── main.go              # Userspace consumer — reads ring buffer, resolves symbols
├── README.md
└── ARCHITECTURE.md      # Deep dive into how it all fits together
```

## Presented At

Bengaluru Systems Meetup — February 2026